/**
 * Client-side SYSVOL zip builder (design doc 17 §3) — the one load-bearing detail.
 *
 * The folder picker yields the SYSVOL subtree as loose files, but the `sysvol`
 * upload kind expects a ZIP the server extracts with its zip-slip guard. The
 * server's `_find_policies_dir` requires EXACTLY one directory above `Policies`
 * (`sysvol_root/<domain>/Policies/{GUID}/...`); a top-level `Policies/` fails
 * silently (0 GPO edges). So every zip member path is rewritten to
 * `"<domain>/Policies/<rel-from-Policies>"` — forward slashes, no leading slash,
 * no `..`, no backslash/drive (the server's guard would reject those).
 *
 * Built deterministically (members sorted, mtime 0, store-only level 0) with
 * fflate (MIT, zero-dep, pure-JS, no network) so repeat ingests are identical.
 */

import { zipSync, type Zippable } from "fflate";

import {
  SYSVOL_MAX_MEMBERS,
  SYSVOL_MAX_TOTAL_UNCOMPRESSED_BYTES,
} from "@/lib/api";

/** ZIP epoch (1980-01-01 UTC) in ms — the earliest valid ZIP mtime (fflate rejects <1980). */
const ZIP_EPOCH_MS = Date.UTC(1980, 0, 1);

export interface SysvolSource {
  file: File;
  relPath: string;
}

export class SysvolZipError extends Error {
  readonly reason: string;
  constructor(reason: string, message: string) {
    super(message);
    this.name = "SysvolZipError";
    this.reason = reason;
  }
}

/** Index of the (case-insensitive) "Policies" segment that has content below it. */
function policiesIndex(segments: string[]): number {
  for (let i = 0; i < segments.length - 1; i++) {
    if (segments[i].toLowerCase() === "policies") return i;
  }
  return -1;
}

/**
 * Compute the locked zip member path for one SYSVOL file:
 * `<domain>/Policies/<everything under Policies>`. A member whose path has no
 * usable `Policies` segment is skipped (returns null) so a stray file can never
 * produce a top-level or `..`-escaping member.
 */
export function sysvolMemberPath(relPath: string, domain: string): string | null {
  const segments = relPath.split(/[\\/]/).filter(Boolean);
  const idx = policiesIndex(segments);
  if (idx < 0) return null;
  const tail = segments.slice(idx + 1).join("/");
  if (!tail || tail.includes("..")) return null;
  return `${domain}/Policies/${tail}`;
}

/**
 * Build the SYSVOL zip (design §3). Enforces the two SYSVOL caps client-side
 * first (mirrors the server) so we never build a zip the server will reject.
 *
 * Returns a `File` named `sysvol.zip` ready for `api.uploadArtifact`.
 *
 * Failure modes:
 *   Throws {@link SysvolZipError} with `reason` `sysvol_too_large` (over a cap) or
 *   `no_policies` (no file carried a usable `Policies/` path).
 */
export async function buildSysvolZip(sources: SysvolSource[], domain: string): Promise<File> {
  const total = sources.reduce((n, s) => n + s.file.size, 0);
  if (sources.length > SYSVOL_MAX_MEMBERS || total > SYSVOL_MAX_TOTAL_UNCOMPRESSED_BYTES) {
    throw new SysvolZipError("sysvol_too_large", "SYSVOL subtree exceeds the extraction caps");
  }
  const safeDomain = domain.replace(/[\\/]/g, "").trim() || "domain";

  // Collect (memberPath -> bytes), sorted by member path for determinism.
  const members: Array<{ path: string; bytes: Uint8Array }> = [];
  for (const s of sources) {
    const path = sysvolMemberPath(s.relPath, safeDomain);
    if (!path) continue;
    const bytes = new Uint8Array(await s.file.arrayBuffer());
    members.push({ path, bytes });
  }
  if (members.length === 0) {
    throw new SysvolZipError("no_policies", "no SYSVOL files under a Policies/ directory");
  }
  members.sort((a, b) => a.path.localeCompare(b.path));

  const zippable: Zippable = {};
  for (const m of members) zippable[m.path] = m.bytes;

  // Store-only (level 0) + a fixed mtime -> deterministic output. The mtime is the
  // ZIP epoch (1980-01-01); fflate rejects anything before 1980, so NOT 0.
  const archive = zipSync(zippable, { level: 0, mtime: ZIP_EPOCH_MS });
  // Copy into a fresh ArrayBuffer-backed Blob (avoid SharedArrayBuffer typing).
  return new File([archive.slice()], "sysvol.zip", { type: "application/zip" });
}
