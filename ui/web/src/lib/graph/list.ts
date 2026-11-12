import type { GraphNode } from "@/lib/api";

/**
 * Pure ordering/summary logic for the graph List view (the results listing that
 * mirrors the Capability Graph canvas and the active Hunter result). Kept out of
 * the component so the sort contract and the honest count copy are unit-testable
 * and deterministic. No React, no I/O.
 *
 * The List renders exactly the slice the canvas renders — a base view, a filtered
 * slice, or a hunt's result set — so the two stay data-consistent (same ids, same
 * labels, same Tier-0 marking). Selection is shared, so a row and its node
 * highlight together.
 */

/**
 * Order slice nodes for the list: Tier-0 / high-value first (the single most
 * important signal), then by kind, then by label — all case-insensitive and
 * tie-broken by node_id so the order is stable across renders. Never mutates the
 * input.
 */
export function orderSliceNodes(nodes: GraphNode[]): GraphNode[] {
  return [...nodes].sort(
    (a, b) =>
      Number(b.highvalue) - Number(a.highvalue) ||
      a.kind.localeCompare(b.kind) ||
      a.label.localeCompare(b.label, undefined, { sensitivity: "base" }) ||
      a.node_id.localeCompare(b.node_id),
  );
}

/** Case-insensitive substring filter over a node's label + kind (the list search). */
export function filterSliceNodes(nodes: GraphNode[], term: string): GraphNode[] {
  const q = term.trim().toLowerCase();
  if (q === "") return nodes;
  return nodes.filter(
    (n) => n.label.toLowerCase().includes(q) || n.kind.toLowerCase().includes(q),
  );
}

/** Honest header summary for the list (total, Tier-0 tally, and a cap note). */
export interface ListSummary {
  total: number;
  tier0: number;
  /** True when the slice was server-capped — the list is a partial view. */
  truncated: boolean;
}

export function listSummary(nodes: GraphNode[], truncated: boolean): ListSummary {
  let tier0 = 0;
  for (const n of nodes) if (n.highvalue) tier0 += 1;
  return { total: nodes.length, tier0, truncated };
}
