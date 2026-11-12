/**
 * Pure hunter-library catalog helpers (shared by the sidebar Hunter Library and
 * the graph's active-hunt wiring). No React, no I/O — just the fixed category
 * order and the deterministic grouping/search over the prebuilt-query catalog.
 */

import type { PrebuiltQuery } from "@/lib/api";

/** Hunter-category display order (doc 09 §4; research 08 §2.4 "fixed hunter order"). */
export const CATEGORY_ORDER: readonly string[] = [
  "Privileged Access",
  "Dangerous ACLs",
  "Shadow Admins",
  "Credential Exposure",
  "Delegation",
  "Stale/Risk",
  "Topology",
  "ADCS",
];

/** Outcome of the currently-active query run (drives the calm "0 found" chip). */
export interface QueryOutcome {
  queryId: string;
  isZero: boolean;
  count: number;
}

/**
 * True when a hunt matches the (already-lowercased, trimmed) search term across
 * its label, description, or category. An empty term matches everything.
 *
 * @param q    one catalog query
 * @param term lowercased, trimmed search term ("" matches all)
 */
export function huntMatches(q: PrebuiltQuery, term: string): boolean {
  if (term.length === 0) return true;
  return (
    q.label.toLowerCase().includes(term) ||
    q.description.toLowerCase().includes(term) ||
    q.category.toLowerCase().includes(term)
  );
}

/**
 * Group a query catalog into ordered [category, hunts] pairs.
 *
 * Categories in {@link CATEGORY_ORDER} lead in that fixed order; any unknown
 * categories trail, alphabetically sorted. Hunt order within a category is the
 * catalog's own (server) order. A non-empty `term` filters hunts first (by
 * label/description/category) and drops categories left empty.
 *
 * Deterministic: identical inputs → identical output. Never throws.
 *
 * @param queries the full prebuilt-query catalog (may be undefined/empty)
 * @param term    raw search text (trimmed + lowercased internally)
 * @returns ordered [category, matching hunts] pairs
 */
export function groupQueries(
  queries: readonly PrebuiltQuery[] | undefined,
  term: string,
): Array<[string, PrebuiltQuery[]]> {
  const needle = term.trim().toLowerCase();
  const byCat = new Map<string, PrebuiltQuery[]>();
  for (const q of queries ?? []) {
    if (!huntMatches(q, needle)) continue;
    const c = q.category || "Other";
    const bucket = byCat.get(c);
    if (bucket) bucket.push(q);
    else byCat.set(c, [q]);
  }
  const ordered: Array<[string, PrebuiltQuery[]]> = [];
  for (const c of CATEGORY_ORDER) {
    const items = byCat.get(c);
    if (items) ordered.push([c, items]);
  }
  for (const c of [...byCat.keys()].sort()) {
    if (!CATEGORY_ORDER.includes(c)) ordered.push([c, byCat.get(c)!]);
  }
  return ordered;
}
