import type { GraphSlice } from "@/lib/api";

/**
 * Walk history + collapse logic for the incremental graph walk (Round 1 B).
 *
 * Expansion was previously one-way (``expandedIds`` only grew; Reset was the only
 * way back). We now record, per expansion, which node ids that step UNIQUELY
 * introduced, so "Walk Back" / "Collapse" can remove exactly that step's leaves
 * without disturbing nodes that another step (or the base view) also brought in.
 * Pure + unit-testable; GraphPage holds the step stack and applies the result.
 */

export interface WalkStep {
  /** The node whose neighbours this step pulled in. */
  seedId: string;
  /** Node ids this step added to the working slice (new to the slice at the time). */
  introduced: string[];
}

/**
 * The node ids safe to remove when dropping ``steps[index]``: the ids that step
 * introduced that are NOT in the base view and were NOT also introduced by any
 * OTHER retained step. Keeping shared nodes avoids tearing a node out from under a
 * different branch of the walk.
 *
 * @returns a set of removable node ids (empty if ``index`` is out of range).
 */
export function removableNodeIds(
  steps: readonly WalkStep[],
  index: number,
  baseIds: Iterable<string>,
): Set<string> {
  const target = steps[index];
  if (!target) return new Set();
  const keep = new Set<string>(baseIds);
  steps.forEach((s, i) => {
    if (i !== index) for (const id of s.introduced) keep.add(id);
  });
  return new Set(target.introduced.filter((id) => !keep.has(id)));
}

/**
 * Remove ``removable`` node ids from a slice, dropping any edge that loses an
 * endpoint. Returns a NEW slice object (new identity → canvas rebuild) with honest
 * recomputed counts and ``layout: "none"`` (client re-lays the remainder; placed
 * nodes stay put via the canvas's incremental path when flagged).
 */
export function applyCollapse(slice: GraphSlice, removable: Set<string>): GraphSlice {
  if (removable.size === 0) return slice;
  const nodes = slice.nodes.filter((n) => !removable.has(n.node_id));
  const keepIds = new Set(nodes.map((n) => n.node_id));
  const edges = slice.edges.filter((e) => keepIds.has(e.source) && keepIds.has(e.target));
  return {
    ...slice,
    nodes,
    edges,
    total_matched: nodes.length,
    returned: nodes.length,
    truncated: false,
    layout: "none",
  };
}
