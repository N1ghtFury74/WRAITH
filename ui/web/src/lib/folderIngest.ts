/**
 * Client-side folder auto-ingest classifier (design doc 17 §1–§2 / §4).
 *
 * Enumerates a picked/dropped folder to a flat file list, reads only the first
 * 4 KiB of each file, sniffs content magic EXACTLY as the server's `_magic_ok`
 * (wraith/api/ingest.py), labels registry hives, groups files into host scopes,
 * and runs the §2.4 decision tree into a typed {@link IngestPlan}. Classification
 * is advisory — the server re-sniffs, re-caps, and zip-slip-guards on upload; this
 * module only auto-routes and pre-screens. Nothing is ever routed or dropped
 * silently: every file becomes a row with ready / needs-host-label / skipped /
 * duplicate status and an explicit reason.
 */

import {
  type ArtifactKindId,
  MAX_UPLOAD_BYTES,
  SYSVOL_MAX_MEMBERS,
  SYSVOL_MAX_TOTAL_UNCOMPRESSED_BYTES,
} from "@/lib/api";
import { slugHostLabel } from "@/lib/utils";

const HEADER_BYTES = 4096;

export type Sniff = "ese" | "regf" | "zip" | "unknown";
export type HiveLabel = "SYSTEM" | "SAM" | "SECURITY" | "SOFTWARE" | null;

export interface PickedFile {
  file: File;
  /** Relative path with the picked root as the first segment, forward slashes. */
  relPath: string;
}

export type PlanStatus = "ready" | "needs-host-label" | "skipped" | "duplicate" | "error";

export interface PlanRow {
  key: string;
  /** Source description (relative path, or "SYSVOL subtree: N files"). */
  source: string;
  scope: string;
  /** Target artifact kind, or null when skipped/unrouted. */
  kind: ArtifactKindId | null;
  status: PlanStatus;
  reason?: string;
  /** host_label (member_sam); editable in the preview. */
  hostLabel?: string;
  /** Single-file upload payload. */
  file?: File;
  /** Companion member-host SYSTEM hive (rides the member_sam upload). */
  companion?: File;
  /** SYSVOL subtree to client-zip at upload time. */
  sysvol?: { files: PickedFile[]; domain: string; memberCount: number; totalBytes: number };
  /** Whether the operator may override this row's kind in the dropdown. */
  overridable: boolean;
}

export interface IngestPlan {
  rows: PlanRow[];
}

// --------------------------------------------------------------------------- //
//  Enumeration (webkitdirectory input + drag-drop walker)                     //
// --------------------------------------------------------------------------- //
/** Flatten a `<input webkitdirectory>` FileList to picked files (relPath set). */
export function filesFromInput(list: FileList): PickedFile[] {
  const out: PickedFile[] = [];
  for (const file of Array.from(list)) {
    const rel = file.webkitRelativePath || file.name;
    out.push({ file, relPath: rel.replace(/\\/g, "/") });
  }
  return out;
}

/** Recursively walk dropped DataTransfer entries into picked files. */
export async function filesFromDrop(items: DataTransferItemList): Promise<PickedFile[]> {
  const roots: FileSystemEntry[] = [];
  for (const item of Array.from(items)) {
    const entry = item.webkitGetAsEntry?.();
    if (entry) roots.push(entry);
  }
  const out: PickedFile[] = [];
  for (const entry of roots) await walkEntry(entry, out);
  return out;
}

async function walkEntry(entry: FileSystemEntry, out: PickedFile[]): Promise<void> {
  if (entry.isFile) {
    const fileEntry = entry as FileSystemFileEntry;
    const file = await new Promise<File>((res, rej) => fileEntry.file(res, rej));
    out.push({ file, relPath: entry.fullPath.replace(/^\/+/, "").replace(/\\/g, "/") });
    return;
  }
  const reader = (entry as FileSystemDirectoryEntry).createReader();
  // readEntries returns in batches; call until it yields an empty array.
  for (;;) {
    const batch = await new Promise<FileSystemEntry[]>((res, rej) => reader.readEntries(res, rej));
    if (batch.length === 0) break;
    for (const child of batch) await walkEntry(child, out);
  }
}

// --------------------------------------------------------------------------- //
//  Content sniff (mirror of server _magic_ok) + hive labelling                //
// --------------------------------------------------------------------------- //
/** Sniff the first-4KiB header exactly as the server's `_magic_ok`. */
export function sniff(b: Uint8Array): Sniff {
  if (b.length >= 8 && b[4] === 0xef && b[5] === 0xcd && b[6] === 0xab && b[7] === 0x89) return "ese";
  if (b.length >= 4 && b[0] === 0x72 && b[1] === 0x65 && b[2] === 0x67 && b[3] === 0x66) return "regf";
  if (
    b.length >= 4 &&
    b[0] === 0x50 &&
    b[1] === 0x4b &&
    ((b[2] === 0x03 && b[3] === 0x04) || (b[2] === 0x05 && b[3] === 0x06))
  ) {
    return "zip";
  }
  return "unknown";
}

const KNOWN_HIVES = new Set(["SYSTEM", "SAM", "SECURITY", "SOFTWARE"]);

function normalizeStem(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? "";
  return base.replace(/\.[^.]*$/, "").toUpperCase();
}

/** REGF base-block embedded original filename (offset 48, 64 bytes, UTF-16LE). */
export function hiveEmbeddedName(buf: Uint8Array): string | null {
  if (buf.length < 48 + 64) return null;
  const raw = new TextDecoder("utf-16le").decode(buf.subarray(48, 48 + 64));
  const nul = raw.indexOf("\u0000");
  const clean = (nul >= 0 ? raw.slice(0, nul) : raw).replace(/[\\/]+$/, "");
  const stem = normalizeStem(clean);
  return stem || null;
}

/** Hive KIND: filename stem first (reliable), else base-block embedded name. */
export function hiveLabel(relPath: string, buf: Uint8Array): HiveLabel {
  const byName = normalizeStem(relPath);
  if (KNOWN_HIVES.has(byName)) return byName as HiveLabel;
  const embedded = hiveEmbeddedName(buf);
  if (embedded && KNOWN_HIVES.has(embedded)) return embedded as HiveLabel;
  return null;
}

// --------------------------------------------------------------------------- //
//  Classification                                                             //
// --------------------------------------------------------------------------- //
interface Classified extends PickedFile {
  segments: string[];
  sniffed: Sniff;
  hive: HiveLabel;
  /** An ESE-sniffed file that is a known work file (temp.edb / edb*.log), not a DIT. */
  eseWork: boolean;
}

function segmentsOf(relPath: string): string[] {
  return relPath.split("/").filter(Boolean);
}

/**
 * Top-level folder names that mean "the capture is organized by ARTIFACT TYPE"
 * (a single-DC forensic-triage export), NOT by host. Case-insensitive basename
 * match. When the content-bearing child dirs are all artifact-type-named, the
 * whole pick is ONE DC scope (never multiple hosts).
 */
const ARTIFACT_TYPE_DIRS = new Set(["ntds", "registry", "sysvol", "config", "hives"]);

/** Known ESE work files that sniff as ESE but are not an ntds.dit (name-exclude). */
function isEseWorkFile(relPath: string): boolean {
  const base = (relPath.split(/[\\/]/).pop() ?? "").toLowerCase();
  return base === "temp.edb" || /^edb.*\.log$/.test(base);
}

/** Index of the (case-insensitive) "Policies" segment with content below it. */
function policiesIndex(segments: string[]): number {
  for (let i = 0; i < segments.length - 1; i++) {
    if (segments[i].toLowerCase() === "policies") return i;
  }
  return -1;
}

async function readHeader(file: File): Promise<Uint8Array> {
  const buf = await file.slice(0, HEADER_BYTES).arrayBuffer();
  return new Uint8Array(buf);
}

/**
 * Classify a flat picked-file list into an {@link IngestPlan} (design §2).
 *
 * Reads each file's 4 KiB header, groups into host scopes, and routes per the
 * §2.4 decision tree. Deterministic: files are processed in relative-path order
 * so duplicate-winner selection and member/sysvol grouping are stable.
 */
export async function buildIngestPlan(picked: PickedFile[]): Promise<IngestPlan> {
  const files: Classified[] = [];
  for (const p of picked) {
    const buf = await readHeader(p.file);
    const sniffed = sniff(buf);
    files.push({
      ...p,
      segments: segmentsOf(p.relPath),
      sniffed,
      hive: sniffed === "regf" ? hiveLabel(p.relPath, buf) : null,
      eseWork: sniffed === "ese" && isEseWorkFile(p.relPath),
    });
  }
  files.sort((a, b) => a.relPath.localeCompare(b.relPath));

  // --- scope detection (design §2.3, corrected for artifact-split captures) ---
  // A content-bearing child DIR is a second-segment directory (some file sits a
  // level deeper under it) that holds a real DIT or a hive. The capture is
  // "artifact-split" (a single DC exported by artifact type: NTDS/ Registry/
  // SYSVOL/) when every such child is artifact-type-named -> ONE DC scope. True
  // multi-host (DC01/ WS01/ WS02/) is >=2 content dirs that are NOT
  // artifact-type-named. A single DC folder with files directly inside (ntds.dit
  // + Windows/.../SYSTEM + SYSVOL/) has <2 host-named content dirs -> one scope.
  const root = files[0]?.segments[0] ?? "root";
  const bySecond = new Map<string, Classified[]>();
  for (const f of files) {
    if (f.segments.length >= 2) {
      const seg = f.segments[1];
      (bySecond.get(seg) ?? bySecond.set(seg, []).get(seg)!).push(f);
    }
  }
  const contentChildren = [...bySecond.entries()]
    .filter(
      ([, fs]) =>
        fs.some((f) => f.segments.length >= 3) && // it's a directory, not a root-level file
        fs.some((f) => (f.sniffed === "ese" && !f.eseWork) || f.sniffed === "regf"),
    )
    .map(([name]) => name);
  const artifactSplit =
    contentChildren.length > 0 &&
    contentChildren.every((name) => ARTIFACT_TYPE_DIRS.has(name.toLowerCase()));
  const hostNamed = contentChildren.filter((name) => !ARTIFACT_TYPE_DIRS.has(name.toLowerCase()));
  const multiHost = !artifactSplit && hostNamed.length >= 2;
  const scopeOf = (f: Classified): string =>
    multiHost ? (f.segments.length >= 2 ? f.segments[1] : root) : root;

  const scopes = new Map<string, Classified[]>();
  for (const f of files) {
    const s = scopeOf(f);
    (scopes.get(s) ?? scopes.set(s, []).get(s)!).push(f);
  }

  const rows: PlanRow[] = [];
  const assigned = new Set<string>();
  // Global single-slot guards (non-multi kinds — one per case).
  let ntdsTaken = false;
  let systemTaken = false;
  let sysvolTaken = false;

  for (const scopeName of [...scopes.keys()].sort()) {
    const scopeFiles = scopes.get(scopeName)!;
    const ese = scopeFiles.filter((f) => f.sniffed === "ese" && !f.eseWork);
    const hives = scopeFiles.filter((f) => f.sniffed === "regf");
    const sysvolFiles = scopeFiles.filter((f) => policiesIndex(f.segments) >= 0);
    const role: "dc" | "member" | "unmapped" = ese.length
      ? "dc"
      : hives.some((h) => h.hive === "SAM")
        ? "member"
        : "unmapped";
    const scopeSlug = slugHostLabel(scopeName) || "host";

    // --- ESE work files (temp.edb / edb*.log) -> explicit skip, never a DIT ---
    for (const f of scopeFiles.filter((f) => f.eseWork)) {
      rows.push(skip(f, scopeName, "ese_work_file"));
      assigned.add(f.relPath);
    }

    // --- ntds.dit (required; one per case) ---
    for (const f of ese) {
      if (!ntdsTaken) {
        ntdsTaken = true;
        rows.push(single(f, "ntds_dit", scopeName));
      } else {
        rows.push(skip(f, scopeName, "additional_dc_reserved"));
      }
      assigned.add(f.relPath);
    }

    // --- registry hives by role ---
    const samInScope = hives.filter((h) => h.hive === "SAM");
    const systemInScope = hives.filter((h) => h.hive === "SYSTEM");
    const memberSystem = systemInScope[0]?.file;

    if (role === "dc") {
      for (const h of systemInScope) {
        if (!systemTaken) {
          systemTaken = true;
          rows.push(single(h, "system_hive", scopeName));
        } else {
          rows.push(skip(h, scopeName, "duplicate_system_hive"));
        }
        assigned.add(h.relPath);
      }
    } else if (role === "member") {
      // One member_sam per scope (multi kind); companion SYSTEM rides it.
      samInScope.forEach((h, i) => {
        if (i === 0) {
          rows.push({
            key: h.relPath,
            source: h.relPath,
            scope: scopeName,
            kind: "member_sam",
            status: scopeSlug ? "ready" : "needs-host-label",
            hostLabel: scopeSlug,
            file: h.file,
            companion: memberSystem,
            overridable: true,
          });
        } else {
          rows.push(skip(h, scopeName, "duplicate_member_sam"));
        }
        assigned.add(h.relPath);
      });
      for (const h of systemInScope) assigned.add(h.relPath); // consumed as companion
    }

    // Any remaining hive in any role with no slot -> explicit skip. The DC's own
    // SAM/SECURITY/SOFTWARE are the common artifact-split case: skipped as
    // "no consuming slot on the DC", NEVER routed to member_sam.
    for (const h of hives) {
      if (assigned.has(h.relPath)) continue;
      let reason: string;
      if (!h.hive) reason = "unlabeled_hive";
      else if (role === "dc") reason = "no_consuming_slot_on_dc";
      else if (role === "unmapped") reason = "hive_without_role";
      else reason = "no_consuming_slot";
      rows.push(skip(h, scopeName, reason));
      assigned.add(h.relPath);
    }

    // --- SYSVOL subtree -> client-zip (one per case) ---
    if (sysvolFiles.length > 0) {
      for (const f of sysvolFiles) assigned.add(f.relPath);
      if (!sysvolTaken) {
        sysvolTaken = true;
        rows.push(sysvolRow(sysvolFiles, scopeName));
      } else {
        rows.push({
          key: `${scopeName}:sysvol-dup`,
          source: `SYSVOL subtree: ${sysvolFiles.length} files`,
          scope: scopeName,
          kind: null,
          status: "duplicate",
          reason: "duplicate_sysvol",
          overridable: false,
        });
      }
    }

    // --- everything else -> explicit skip (unrecognized / pre-made zip) ---
    for (const f of scopeFiles) {
      if (assigned.has(f.relPath)) continue;
      const reason = isEseWorkFile(f.relPath)
        ? "ese_work_file"
        : f.sniffed === "zip"
          ? "unrouted_zip"
          : "unrecognized";
      rows.push(skip(f, scopeName, reason));
      assigned.add(f.relPath);
    }
  }

  return { rows };
}

function single(f: Classified, kind: ArtifactKindId, scope: string): PlanRow {
  const overCap = f.file.size > MAX_UPLOAD_BYTES[kind];
  return {
    key: f.relPath,
    source: f.relPath,
    scope,
    kind,
    status: overCap ? "skipped" : "ready",
    reason: overCap ? `exceeds_cap:${kind}` : undefined,
    file: f.file,
    overridable: true,
  };
}

function skip(f: Classified, scope: string, reason: string): PlanRow {
  return {
    key: f.relPath,
    source: f.relPath,
    scope,
    kind: null,
    status: "skipped",
    reason,
    file: f.file,
    overridable: true,
  };
}

function sysvolRow(files: Classified[], scope: string): PlanRow {
  const totalBytes = files.reduce((n, f) => n + f.file.size, 0);
  const memberCount = files.length;
  // Domain = the dir name immediately above the first "Policies" segment, else a
  // synthesized literal "domain" (the server ignores its value but REQUIRES
  // exactly one dir above Policies — design §3.1).
  const first = files[0];
  const idx = policiesIndex(first.segments);
  const domain = idx >= 1 ? first.segments[idx - 1] : "domain";
  const tooLarge =
    totalBytes > SYSVOL_MAX_TOTAL_UNCOMPRESSED_BYTES || memberCount > SYSVOL_MAX_MEMBERS;
  return {
    key: `${scope}:sysvol`,
    source: `SYSVOL subtree: ${memberCount} files`,
    scope,
    kind: "sysvol",
    status: tooLarge ? "skipped" : "ready",
    reason: tooLarge ? "sysvol_too_large" : undefined,
    sysvol: { files: files.map((f) => ({ file: f.file, relPath: f.relPath })), domain, memberCount, totalBytes },
    overridable: false,
  };
}
