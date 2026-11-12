/**
 * Pure helpers for the multi-source / multi-domain UI (M-MS5b). No React, no
 * fetch — just deterministic shaping of the API counts into the honesty cards so
 * the logic is unit-testable and the components stay thin.
 *
 * Honesty polarity (same as the GPO / AD CS coverage cards): a count is shown ONLY
 * when the backend actually measured it (its key is present in coverage/skip). A
 * missing key is NOT rendered as a reassuring "0" — absence means the branch may
 * not have run, which is a different claim than "measured zero".
 */
import type { SourceCoverage, SourceInfo } from "@/lib/api";

/** Merged coverage + skip tallies across every source in a case. */
export interface AggregatedCounts {
  coverage: Record<string, number>;
  skip: Record<string, number>;
}

/** One signal row in the cross-domain honesty card. */
export interface CrossDomainRow {
  key: string;
  label: string;
  count: number;
}

/** The cross-domain honesty card's structured content. */
export interface CrossDomainSignals {
  found: CrossDomainRow[];
  gaps: CrossDomainRow[];
  mismatches: CrossDomainRow[];
  /** True when NO cross-domain key was measured at all (honest empty-state). */
  empty: boolean;
}

/** Sum two count maps into an accumulator (mutates + returns `acc`). */
function addInto(acc: Record<string, number>, src: Record<string, number>): Record<string, number> {
  for (const [k, v] of Object.entries(src)) {
    acc[k] = (acc[k] ?? 0) + (typeof v === "number" ? v : 0);
  }
  return acc;
}

/** Aggregate per-source coverage/skip tallies across all of a case's sources. */
export function aggregateCounts(coverages: SourceCoverage[]): AggregatedCounts {
  const coverage: Record<string, number> = {};
  const skip: Record<string, number> = {};
  for (const c of coverages) {
    addInto(coverage, c.coverage_counts ?? {});
    addInto(skip, c.skip_counts ?? {});
  }
  return { coverage, skip };
}

/** Coverage keys that mean "a cross-domain relation was successfully wired". */
const FOUND_KEYS: ReadonlyArray<[string, string]> = [
  ["edges.xd_trust", "Trust edges"],
  ["edges.xd_trust_parent_child", "Parent-child trusts (FQDN-inferred)"],
  ["edges.xd_trust_tree_root", "Tree-root trusts (FQDN-inferred)"],
  ["edges.xd_trust_partner_resolved", "Trust partners resolved"],
  ["edges.xd_fsp_resolved", "FSPs resolved to owning domain"],
  ["edges.xd_sidhistory_cross_domain", "sIDHistory bridges (cross-domain)"],
];

/** Skip keys that mean "a cross-domain relation could not be fully resolved". */
const GAP_KEYS: ReadonlyArray<[string, string]> = [
  ["edges.xd_fsp_owning_domain_not_ingested", "FSPs unresolved — owning domain not ingested"],
  ["edges.xd_fsp_principal_unresolved_in_ingested_domain", "FSPs unresolved in an ingested domain"],
  ["edges.xd_fsp_principal_type_unknown", "FSP principal type unknown"],
  ["edges.xd_trust_partner_not_ingested", "Trust partner domain not ingested"],
  ["edges.xd_trust_type_undetermined", "Trust type undetermined"],
  ["edges.xd_sidhistory_owning_domain_not_ingested", "sIDHistory owning domain not ingested"],
  ["edges.xd_gc_partial_replica", "GC partial-replica shadows (never win over a full copy)"],
];

/** Declaration-vs-derived reconciliation keys (contract §1.4). */
const MISMATCH_KEYS: ReadonlyArray<[string, string]> = [
  ["source_label_domain_mismatch", "Declared domain disagreed with the ntds.dit (derived value used)"],
  ["case_shape_mismatch:multiple_domains_detected", "More domains detected than declared"],
  ["case_shape_mismatch:same_domain_two_dcs", "Two sources are the same domain (a multi-DC case)"],
];

function rowsFor(
  defs: ReadonlyArray<[string, string]>,
  counts: Record<string, number>,
): CrossDomainRow[] {
  const out: CrossDomainRow[] = [];
  for (const [key, label] of defs) {
    if (key in counts) out.push({ key, label, count: counts[key] });
  }
  return out;
}

/**
 * Shape the aggregated counts into the cross-domain honesty card. Only measured
 * keys appear; `empty` is true when nothing cross-domain was measured so the card
 * can render an honest "no cross-domain relations observed" rather than a blank.
 */
export function crossDomainSignals(agg: AggregatedCounts): CrossDomainSignals {
  const found = rowsFor(FOUND_KEYS, agg.coverage);
  const gaps = rowsFor(GAP_KEYS, agg.skip);
  const mismatches = rowsFor(MISMATCH_KEYS, agg.skip);
  return { found, gaps, mismatches, empty: found.length === 0 && gaps.length === 0 };
}

/** The set of distinct derived domains across sources (FQDN preferred, id fallback). */
export function distinctDomains(sources: SourceInfo[]): string[] {
  const set = new Set<string>();
  for (const s of sources) {
    const d = s.domain_fqdn ?? s.domain_id;
    if (d) set.add(d);
  }
  return [...set].sort();
}

/** The set of distinct forests across sources (cross-forest when >1). */
export function distinctForests(sources: SourceInfo[]): string[] {
  return [...new Set(sources.map((s) => s.forest_id).filter(Boolean))].sort();
}

/** True when a source's operator label disagrees with the ntds.dit-derived domain. */
export function hasLabelMismatch(s: SourceInfo): boolean {
  if (!s.declared_domain || !s.domain_fqdn) return false;
  return s.declared_domain.trim().toLowerCase() !== s.domain_fqdn.trim().toLowerCase();
}
