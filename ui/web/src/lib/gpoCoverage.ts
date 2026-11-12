/**
 * Pure Group Policy coverage-honesty logic (Research 22 §B).
 *
 * This is the INVERSE polarity of the AD CS coverage card. AD CS warns about
 * UNDER-statement — a blank/undecidable ESC verdict might be hiding danger. GPO
 * inferred edges are the opposite: a SUPERSET / OVER-statement. WRAITH emits the
 * union of every non-disabled GPO link and, dead-disk, cannot replay live RSoP
 * (security filtering, WMI filters, block-inheritance, link precedence,
 * enforcement). So the honest message is "candidate paths to VERIFY — this set
 * over-states, never under-states; there are NO missed GPO paths here." A
 * degraded branch is never presented as "safe"; the not-run state says "not
 * analyzed", never "none exist".
 *
 * Mirrors the engine counter keys in `wraith/gpo/engine.py`:
 *   - `_COV_*` keys land in `coverage_counts` (the positive emission figures).
 *   - `_SKIP_*` keys land in `skip_counts` (the counted gaps).
 * The engine omits any key whose count is 0, so the `n(..)` missing⇒0 helper is
 * the single source of truth for every read. No React, no I/O — just the
 * deterministic mapping.
 */

// --- coverage-count keys (gpo.*, one source of truth, mirrored from engine) ---
export const COV_FOLDERS_MATCHED = "gpo.folders_matched";
export const COV_ADMIN_TO_EDGES = "gpo.admin_to_edges";
export const COV_LOCAL_GROUP_EDGES = "gpo.local_group_edges";
export const COV_PRIVILEGE_EDGES = "gpo.privilege_edges";

// --- skip-count keys (gpo.*, one source of truth, mirrored from engine) -------
export const SKIP_SYSVOL_MISSING = "gpo.sysvol_missing";
export const SKIP_ORPHAN_FOLDER = "gpo.orphan_folder";
export const SKIP_SCOPE_COMPUTER_UNRESOLVED = "gpo.scope_computer_unresolved";
export const SKIP_MEMBER_NAME_UNRESOLVED = "gpo.member_name_unresolved";
export const SKIP_INF_PARSE_ERROR = "gpo.inf_parse_error";
export const SKIP_PREG_PARSE_ERROR = "gpo.preg_parse_error";
export const SKIP_GPP_PARSE_ERROR = "gpo.gpp_parse_error";
export const SKIP_FILE_READ_ERROR = "gpo.file_read_error";
export const SKIP_FILE_OVERSIZE = "gpo.file_oversize";
export const SKIP_GPP_CPASSWORD_FINDING = "gpo.gpp_cpassword_finding";

/**
 * Tone for one GPO coverage gap row. `degraded` = a branch that could hide real
 * terrain if left unread (missing SYSVOL, unresolved scope, a reversible
 * cpassword); `muted` = a benign, honestly-counted skip (orphan folder,
 * unresolved member, malformed/oversize file).
 */
export type GpoCoverageTone = "degraded" | "muted";

/** One operator-facing GPO coverage gap row (a counted, named honesty signal). */
export interface GpoCoverageRow {
  /** Stable key for React + tests. */
  id: string;
  /** Short row title. */
  label: string;
  /** Severity tone (see {@link GpoCoverageTone}). */
  tone: GpoCoverageTone;
  /** Plain-English, no-false-safe explanation. */
  note: string;
  /** The raw counted value driving this row (always > 0 when emitted). */
  count: number;
}

/** The deduped-headline-free emission figures for the live-counts strip. */
export interface GpoHeadline {
  /** `gpo.folders_matched` — SYSVOL policy folders matched to a GPO object. */
  gposProcessed: number;
  /**
   * `gpo.local_group_edges + gpo.privilege_edges` — summed client-side. These are
   * pre-dedup, per-instance emission counters, so this is honestly "inferred edges
   * emitted", NOT a distinct-edge total (the deduped total is not exposed).
   */
  inferredEdges: number;
  /** `gpo.admin_to_edges` — per-instance AdminTo emissions of GPO origin. */
  adminToEdges: number;
  /** `gpo.local_group_edges` — per-instance restricted-group / GPP local pushes. */
  localGroupEdges: number;
  /** `gpo.privilege_edges` — per-instance user-rights-assignment emissions. */
  privilegeEdges: number;
}

function n(counts: Record<string, number>, key: string): number {
  const v = counts[key];
  return typeof v === "number" && v > 0 ? v : 0;
}

/**
 * The GPO live-counts strip figures, read only from `coverage_counts`. Every
 * missing key reads as 0 (the engine omits zero-count keys). `inferredEdges` is
 * summed client-side from the two per-instance edge counters and is labeled
 * "inferred edges emitted", never "distinct edges".
 */
export function gpoHeadline(coverage: Record<string, number>): GpoHeadline {
  const localGroupEdges = n(coverage, COV_LOCAL_GROUP_EDGES);
  const privilegeEdges = n(coverage, COV_PRIVILEGE_EDGES);
  return {
    gposProcessed: n(coverage, COV_FOLDERS_MATCHED),
    inferredEdges: localGroupEdges + privilegeEdges,
    adminToEdges: n(coverage, COV_ADMIN_TO_EDGES),
    localGroupEdges,
    privilegeEdges,
  };
}

/**
 * The honest GPO coverage gap rows for a run's `skip_counts` — only the branches
 * that actually fired (count > 0). Parse errors (inf/preg/gpp) and file errors
 * (read/oversize) are each summed into one row. Returns `[]` when nothing GPO was
 * skipped. Deterministic order: missing/unresolved terrain first (degraded),
 * benign skips next (muted), reversible-cpassword finding last (degraded).
 */
export function summarizeGpoCoverage(skip: Record<string, number>): GpoCoverageRow[] {
  const sysvolMissing = n(skip, SKIP_SYSVOL_MISSING);
  const orphanFolder = n(skip, SKIP_ORPHAN_FOLDER);
  const scopeComputer = n(skip, SKIP_SCOPE_COMPUTER_UNRESOLVED);
  const memberName = n(skip, SKIP_MEMBER_NAME_UNRESOLVED);
  const parseErrors =
    n(skip, SKIP_INF_PARSE_ERROR) + n(skip, SKIP_PREG_PARSE_ERROR) + n(skip, SKIP_GPP_PARSE_ERROR);
  const fileErrors = n(skip, SKIP_FILE_READ_ERROR) + n(skip, SKIP_FILE_OVERSIZE);
  const cpassword = n(skip, SKIP_GPP_CPASSWORD_FINDING);

  const rows: GpoCoverageRow[] = [];

  if (sysvolMissing > 0) {
    rows.push({
      id: SKIP_SYSVOL_MISSING,
      label: "GPOs with no SYSVOL files",
      tone: "degraded",
      note:
        "These GPO objects exist in the directory but their SYSVOL folder was not in the upload, " +
        "so their settings could not be read. Their edges are absent because the files are missing, " +
        "NOT because the GPO is empty — upload the full SYSVOL to decide them.",
      count: sysvolMissing,
    });
  }

  if (orphanFolder > 0) {
    rows.push({
      id: SKIP_ORPHAN_FOLDER,
      label: "SYSVOL folders with no directory object",
      tone: "muted",
      note:
        "Policy folders on disk with no matching GPO object in ntds.dit (orphaned/stale) — " +
        "skipped and counted, never guessed.",
      count: orphanFolder,
    });
  }

  if (scopeComputer > 0) {
    rows.push({
      id: SKIP_SCOPE_COMPUTER_UNRESOLVED,
      label: "GPO applies but no computer in scope",
      tone: "degraded",
      note:
        "A high-value Group Policy setting was found but no computer resolved in the linked " +
        "containers' scope, so no edge was emitted. Counted, not dropped silently.",
      count: scopeComputer,
    });
  }

  if (memberName > 0) {
    rows.push({
      id: SKIP_MEMBER_NAME_UNRESOLVED,
      label: "Members not resolvable to a SID",
      tone: "muted",
      note:
        "A group member was named rather than given as a SID and could not be resolved offline; " +
        "its edge was suppressed and counted.",
      count: memberName,
    });
  }

  if (parseErrors > 0) {
    rows.push({
      id: "gpo.parse_error",
      label: "Unparseable policy files",
      tone: "muted",
      note:
        "Malformed GptTmpl.inf / Registry.pol / Groups.xml files were skipped and counted — " +
        "their settings are not represented.",
      count: parseErrors,
    });
  }

  if (fileErrors > 0) {
    rows.push({
      id: "gpo.file_error",
      label: "Oversize/unreadable files",
      tone: "muted",
      note:
        "SYSVOL files that were unreadable or over the 8 MiB safety cap were skipped and counted.",
      count: fileErrors,
    });
  }

  if (cpassword > 0) {
    rows.push({
      id: SKIP_GPP_CPASSWORD_FINDING,
      label: "GPP cpasswords found",
      tone: "degraded",
      note:
        "Reversible GPP cpassword(s) were found in SYSVOL and routed to the encrypted finding " +
        "store (redacted) — see dossiers, not the graph.",
      count: cpassword,
    });
  }

  return rows;
}
