/**
 * Pure Enterprise-CA-host coverage-honesty logic (module 35b, blog 1.10 Part B).
 *
 * This is the SAME polarity as the AD CS card and the INVERSE of the GPO card:
 * for the CA host, MORE evidence means MORE findings, never fewer. Dead-disk,
 * ManageCA / ManageCertificates and ESC6 / ESC7 / ESC11 / ESC16 live only in the
 * CA host's own registry, not in ntds.dit. So WITHOUT the CA host hive they are
 * UNDECIDABLE — counted gaps (`adcs.ca_host_facts_absent`), never false-negatives,
 * and never "clean". WITH it they become decidable and emit real edges/findings.
 *
 * The SYSTEM-vs-SOFTWARE split is stated honestly: the SYSTEM hive unlocks the CA
 * roles + ESC (Security descriptor + EditFlags/InterfaceFlags/DisableExtensionList);
 * the OPTIONAL SOFTWARE hive adds only the machine-wide DCOM activation posture
 * (`adcs.dcom_restrictions_absent` counts its absence). Numbers come only from the
 * run's `coverage_counts` / `skip_counts` — nothing is invented client-side.
 *
 * Mirrors the engine count keys in `wraith/analysis/adcs_esc.py`. No React, no I/O.
 */

// --- coverage-count keys (edges/findings emitted; mirrored from the engine) ----
export const COV_MANAGE_CA = "edges.manage_ca";
export const COV_MANAGE_CERTIFICATES = "edges.manage_certificates";
export const COV_ESC6A = "edges.adcs_esc6a";
export const COV_CA_NODE_FINDINGS = "adcs.ca_node_findings";

// --- skip-count keys (counted gaps; mirrored from the engine) ------------------
export const SKIP_CA_HOST_FACTS_ABSENT = "adcs.ca_host_facts_absent";
export const SKIP_CA_HOST_HIVE_READ = "adcs.ca_host_hive_read_error";
export const SKIP_CA_HOST_NAME_MISMATCH = "adcs.ca_host_name_mismatch";
export const SKIP_CA_HOST_CORRELATION_AMBIGUOUS = "adcs.ca_host_correlation_ambiguous";
export const SKIP_CA_SECURITY_ABSENT = "adcs.ca_security_absent";
export const SKIP_CA_SECURITY_PARSE = "adcs.ca_security_parse_error";
export const SKIP_CA_SECURITY_ACE_SKIPPED = "adcs.ca_security_ace_skipped";
export const SKIP_CA_GRANTEE_UNRESOLVED = "adcs.ca_grantee_unresolved";
export const SKIP_DCOM_ABSENT = "adcs.dcom_restrictions_absent";
export const SKIP_DCOM_SD_PARSE = "adcs.dcom_sd_parse_error";

/** Honest tone for one CA-host data-quality gap row. */
export type CaHostGapTone = "undecidable" | "muted";

/** One operator-facing CA-host data-quality gap row (a counted honesty signal). */
export interface CaHostGapRow {
  /** Stable key for React + tests. */
  id: string;
  /** Short row title. */
  label: string;
  /** `undecidable` = a verdict could not be decided (not "clean"); `muted` = a
   * benign, honestly-counted decode skip. */
  tone: CaHostGapTone;
  /** Plain-English, no-false-safe explanation. */
  note: string;
  /** The raw counted value driving this row (always > 0 when emitted). */
  count: number;
}

/** The decidability headline for the CA-host plane. */
export type CaHostState = "undecidable" | "decidable";

/** The honest CA-host coverage summary (what the card renders). */
export interface CaHostCoverage {
  /** False when there is nothing CA-host to surface (the card hides entirely). */
  relevant: boolean;
  /** `undecidable` = the CA host registry was not read, so the CA-role/ESC verdicts
   * are counted gaps; `decidable` = the hive was read and those are resolved. */
  state: CaHostState;
  /** True when the `ca_host_registry` artifact is present in the case. */
  hivePresent: boolean;
  /** ManageCA/ManageCertificates + ESC6/7/11/16 undecidable because no CA host facts. */
  factsAbsent: number;
  /** WITH-state decided emissions. */
  manageCa: number;
  manageCertificates: number;
  esc6a: number;
  nodeFindings: number;
  /** Sum of the WITH-state decided emissions (edges + node findings). */
  decidedTotal: number;
  /** SOFTWARE/DCOM posture: > 0 ⇒ DCOM undecidable (SOFTWARE hive not contributing). */
  dcomAbsent: number;
  /** Counted CA-host data-quality gaps (hive read error, mismatch, parse…). */
  gaps: CaHostGapRow[];
}

function n(counts: Record<string, number>, key: string): number {
  const v = counts[key];
  return typeof v === "number" && v > 0 ? v : 0;
}

/**
 * Summarize the CA-host coverage plane from a run's `coverage_counts` + `skip_counts`
 * and whether the `ca_host_registry` artifact is present. `hivePresent` drives the
 * WITHOUT/WITH headline; the counts refine it. The state is `decidable` only when the
 * hive is present AND nothing blocked the CA-host facts (no absent/read-error) — so a
 * mis-correlated or unreadable hive never reads as "clean". Deterministic gap order:
 * hive-level undecidable blockers first, then benign decode skips.
 */
export function summarizeCaHostCoverage(
  coverage: Record<string, number>,
  skip: Record<string, number>,
  hivePresent: boolean,
): CaHostCoverage {
  const factsAbsent = n(skip, SKIP_CA_HOST_FACTS_ABSENT);
  const hiveRead = n(skip, SKIP_CA_HOST_HIVE_READ);
  const nameMismatch = n(skip, SKIP_CA_HOST_NAME_MISMATCH);
  const correlationAmbiguous = n(skip, SKIP_CA_HOST_CORRELATION_AMBIGUOUS);
  const securityAbsent = n(skip, SKIP_CA_SECURITY_ABSENT);
  const securityParse = n(skip, SKIP_CA_SECURITY_PARSE);
  const aceSkipped = n(skip, SKIP_CA_SECURITY_ACE_SKIPPED);
  const granteeUnresolved = n(skip, SKIP_CA_GRANTEE_UNRESOLVED);
  const dcomAbsent = n(skip, SKIP_DCOM_ABSENT);
  const dcomSdParse = n(skip, SKIP_DCOM_SD_PARSE);

  const manageCa = n(coverage, COV_MANAGE_CA);
  const manageCertificates = n(coverage, COV_MANAGE_CERTIFICATES);
  const esc6a = n(coverage, COV_ESC6A);
  const nodeFindings = n(coverage, COV_CA_NODE_FINDINGS);
  const decidedTotal = manageCa + manageCertificates + esc6a + nodeFindings;

  const gaps: CaHostGapRow[] = [];

  if (hiveRead > 0) {
    gaps.push({
      id: SKIP_CA_HOST_HIVE_READ,
      label: "CA host hive unreadable",
      tone: "undecidable",
      note:
        "The CA host registry hive was supplied but could not be read — the CA-role / ESC " +
        "verdicts stay undecidable on this CA (NOT 'clean').",
      count: hiveRead,
    });
  }
  if (nameMismatch > 0) {
    gaps.push({
      id: SKIP_CA_HOST_NAME_MISMATCH,
      label: "CA host did not correlate to a CA",
      tone: "undecidable",
      note:
        "The uploaded CA host hive did not match any Enterprise-CA object in the directory, so its " +
        "facts could not be applied. Check the CA host FQDN; its findings remain undecidable until " +
        "it correlates.",
      count: nameMismatch,
    });
  }
  if (correlationAmbiguous > 0) {
    gaps.push({
      id: SKIP_CA_HOST_CORRELATION_AMBIGUOUS,
      label: "CA host correlation ambiguous",
      tone: "undecidable",
      note:
        "The CA host hive matched more than one CA and WRAITH would not guess which — the facts " +
        "were not applied and are counted, never attributed to the wrong CA.",
      count: correlationAmbiguous,
    });
  }
  if (securityAbsent > 0) {
    gaps.push({
      id: SKIP_CA_SECURITY_ABSENT,
      label: "CA Security descriptor absent",
      tone: "undecidable",
      note:
        "The CA's Security registry value was not present in the hive, so ManageCA / " +
        "ManageCertificates could not be decided for that CA (counted, not 'none').",
      count: securityAbsent,
    });
  }
  if (securityParse > 0) {
    gaps.push({
      id: SKIP_CA_SECURITY_PARSE,
      label: "CA Security descriptor unparseable",
      tone: "muted",
      note: "A CA Security descriptor could not be parsed and was skipped and counted, never guessed.",
      count: securityParse,
    });
  }
  if (dcomSdParse > 0) {
    gaps.push({
      id: SKIP_DCOM_SD_PARSE,
      label: "DCOM descriptor unparseable",
      tone: "muted",
      note: "A machine-wide DCOM security descriptor could not be parsed and was skipped and counted.",
      count: dcomSdParse,
    });
  }
  if (aceSkipped > 0) {
    gaps.push({
      id: SKIP_CA_SECURITY_ACE_SKIPPED,
      label: "CA ACEs skipped",
      tone: "muted",
      note: "Individual CA-security ACEs that could not be decoded were skipped and counted.",
      count: aceSkipped,
    });
  }
  if (granteeUnresolved > 0) {
    gaps.push({
      id: SKIP_CA_GRANTEE_UNRESOLVED,
      label: "CA grantees unresolved",
      tone: "muted",
      note:
        "A principal granted a CA right could not be resolved to a directory object; its edge was " +
        "suppressed and counted, never attached to a guessed identity.",
      count: granteeUnresolved,
    });
  }

  // Decidable only when the hive is present AND nothing blocked its facts. A
  // mis-correlated / unreadable / security-absent hive is NEVER rendered as clean.
  const blocked =
    factsAbsent + hiveRead + nameMismatch + correlationAmbiguous + securityAbsent;
  const state: CaHostState = hivePresent && blocked === 0 ? "decidable" : "undecidable";

  const relevant =
    hivePresent ||
    factsAbsent > 0 ||
    decidedTotal > 0 ||
    dcomAbsent > 0 ||
    gaps.length > 0;

  return {
    relevant,
    state,
    hivePresent,
    factsAbsent,
    manageCa,
    manageCertificates,
    esc6a,
    nodeFindings,
    decidedTotal,
    dcomAbsent,
    gaps,
  };
}
