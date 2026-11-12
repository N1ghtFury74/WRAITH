/**
 * Pure AD CS coverage-honesty logic (doc 16 §C, domain-expert requirement).
 *
 * The ESC pass always runs, so a run's `skip_counts` ledger carries the AD CS
 * accounting keys even when zero. The hunter's danger is misreading a NULL ESC
 * verdict as "clean". These helpers turn the raw engine skip counts into honest,
 * operator-facing rows that keep the two undecidability PLANES distinct:
 *
 *   - "no DC SYSTEM hive uploaded"  (`adcs.dc_config_undecidable_no_hive`) vs
 *   - "hive present but cert-binding value unset" (the rest of
 *     `adcs.dc_config_absent`) vs
 *   - "hive present but unreadable" (`adcs.dc_config_hive_read_error`)
 *
 * The CA-host plane (`adcs.ca_host_facts_absent`, ESC6/7/11/16, ManageCA) is owned
 * by the dedicated CA-host coverage card (`caHostCoverage.ts`), which carries the
 * WITHOUT/WITH polarity + the SYSTEM-vs-SOFTWARE split — so this module stays the
 * DC-SYSTEM-hive plane (ESC9/ESC10) only and never double-reports it.
 * `hive_read=False` is NEVER rendered as safe/strong — it is always a loud counted
 * gap. No React, no I/O — just the deterministic mapping.
 *
 * Mirrors the engine skip keys in `wraith/analysis/adcs_esc.py`.
 */

// --- engine skip-count keys (one source of truth, mirrored from the engine) --
export const SKIP_DC_CONFIG_ABSENT = "adcs.dc_config_absent";
export const SKIP_DC_CONFIG_NO_HIVE = "adcs.dc_config_undecidable_no_hive";
export const SKIP_DC_CONFIG_HIVE_READ_ERROR = "adcs.dc_config_hive_read_error";
export const SKIP_CA_HOST_FACTS_ABSENT = "adcs.ca_host_facts_absent";
export const SKIP_ESC_TEMPLATE_UNRESOLVED = "adcs.esc_template_unresolved";
export const SKIP_ESC_FLAG_PARSE_ERROR = "adcs.esc_flag_parse_error";

/** Honest status tone for one AD CS coverage row. */
export type AdcsCoverageStatus = "undecidable" | "gap";

/** One operator-facing AD CS coverage row (a counted, named honesty signal). */
export interface AdcsCoverageRow {
  /** Stable key for React + tests. */
  id: string;
  /** Short plane title. */
  label: string;
  /** `undecidable` = a verdict could not be decided (not "clean"); `gap` = a
   * data-quality skip (malformed anchor/flag). */
  status: AdcsCoverageStatus;
  /** Plain-English, no-false-safe explanation. */
  note: string;
  /** The raw counted-gap value driving this row (always > 0 when emitted). */
  count: number;
}

function n(skip: Record<string, number>, key: string): number {
  const v = skip[key];
  return typeof v === "number" && v > 0 ? v : 0;
}

/**
 * The honest AD CS warning rows for a run's `skip_counts` — only the branches that
 * actually fired (count > 0), each keeping its plane distinct. Returns `[]` when
 * nothing AD CS was skipped. Deterministic order: DC-config (ESC9/ESC10) planes,
 * then data-quality gaps. The CA-host plane lives in the dedicated CA-host card.
 */
export function summarizeAdcsCoverage(skip: Record<string, number>): AdcsCoverageRow[] {
  const absent = n(skip, SKIP_DC_CONFIG_ABSENT);
  const noHive = n(skip, SKIP_DC_CONFIG_NO_HIVE);
  const readError = n(skip, SKIP_DC_CONFIG_HIVE_READ_ERROR);
  const templateUnresolved = n(skip, SKIP_ESC_TEMPLATE_UNRESOLVED);
  const flagParse = n(skip, SKIP_ESC_FLAG_PARSE_ERROR);

  // The "hive present but a specific cert-binding value is unset" subset is the
  // part of dc_config_absent NOT attributable to a missing hive (and not a read
  // error). Never negative.
  const valueUnset = Math.max(0, absent - noHive - readError);

  const rows: AdcsCoverageRow[] = [];

  if (noHive > 0) {
    rows.push({
      id: SKIP_DC_CONFIG_NO_HIVE,
      label: "ESC9 / ESC10 — no DC SYSTEM hive",
      status: "undecidable",
      note:
        "No DC SYSTEM hive uploaded — the cert-mapping registry is unread, so ESC9/ESC10 " +
        "are undecidable. A null ESC9/ESC10 result here is NOT a safe posture; upload the " +
        "DC SYSTEM hive to decide it.",
      count: noHive,
    });
  }

  if (readError > 0) {
    rows.push({
      id: SKIP_DC_CONFIG_HIVE_READ_ERROR,
      label: "ESC9 / ESC10 — hive unreadable",
      status: "undecidable",
      note:
        "The DC SYSTEM hive was supplied but could not be read — ESC9/ESC10 stay " +
        "undecidable (not 'clean').",
      count: readError,
    });
  }

  if (valueUnset > 0) {
    rows.push({
      id: SKIP_DC_CONFIG_ABSENT,
      label: "ESC9 / ESC10 — cert-binding value unset",
      status: "undecidable",
      note:
        "The DC SYSTEM hive was read, but a cert-binding registry value is unset — ESC9/ESC10 " +
        "remain undecidable on this DC (NOT 'clean'). Verdicts hold only for the imaged DC.",
      count: valueUnset,
    });
  }

  if (templateUnresolved > 0) {
    rows.push({
      id: SKIP_ESC_TEMPLATE_UNRESOLVED,
      label: "ESC template unresolved",
      status: "gap",
      note: "An ESC derivation anchor was missing/malformed and was counted, never guessed.",
      count: templateUnresolved,
    });
  }

  if (flagParse > 0) {
    rows.push({
      id: SKIP_ESC_FLAG_PARSE_ERROR,
      label: "ESC flag parse error",
      status: "gap",
      note: "A template PKI flag could not be parsed and was counted, never guessed.",
      count: flagParse,
    });
  }

  return rows;
}

/**
 * Whether ESC9/ESC10 were DECIDABLE on the imaged DC: the DC SYSTEM hive is present
 * AND no dc_config branch was left undecidable (absent + read-error both zero).
 * Used only to render a calm affirmative line — and ONLY when the hive is present,
 * so `hive_read=False` can never surface as a safe posture.
 */
export function escDcDecidable(
  skip: Record<string, number>,
  systemHivePresent: boolean,
): boolean {
  if (!systemHivePresent) return false;
  return n(skip, SKIP_DC_CONFIG_ABSENT) === 0 && n(skip, SKIP_DC_CONFIG_HIVE_READ_ERROR) === 0;
}
