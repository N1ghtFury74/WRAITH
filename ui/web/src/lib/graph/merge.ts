import type { GraphEdge, GraphNode, GraphSlice } from "@/lib/api";

/**
 * Incremental-walk helpers. The Capability Graph lets you start from a seed
 * (Tier-0 by default) and click a node to pull its neighbours into the canvas,
 * walking the attack graph hop by hop (Linkurious/BloodHound-style) instead of
 * dumping the whole forest. These merge the fetched neighbourhood into the
 * current working slice.
 */

/** Max nodes kept in one interactive walk before further expansion is refused.
 * Client-side ForceAtlas2 stays fluid well below this (see SigmaCanvas). */
export const WALK_NODE_CAP = 600;

/**
 * Merge slice `add` into `base`: de-duplicate nodes by `node_id` and edges by
 * `edge_id`, keeping every edge whose endpoints are both present. Positions are
 * dropped (`layout: "none"`) so the client re-lays out the combined graph; the
 * canvas preserves already-placed nodes so only the new ones animate in.
 * Returns a NEW object (new identity → canvas rebuild).
 */
export function mergeSlices(base: GraphSlice, add: GraphSlice): GraphSlice {
  const nodes = new Map<string, GraphNode>();
  for (const n of base.nodes) nodes.set(n.node_id, n);
  for (const n of add.nodes) if (!nodes.has(n.node_id)) nodes.set(n.node_id, n);

  const edges = new Map<string, GraphEdge>();
  for (const e of base.edges) edges.set(e.edge_id, e);
  for (const e of add.edges) if (!edges.has(e.edge_id)) edges.set(e.edge_id, e);

  const present = new Set(nodes.keys());
  const nodeList = [...nodes.values()];
  const edgeList = [...edges.values()].filter(
    (e) => present.has(e.source) && present.has(e.target),
  );

  return {
    ...base,
    nodes: nodeList,
    edges: edgeList,
    total_matched: nodeList.length,
    returned: nodeList.length,
    truncated: false,
    layout: "none",
  };
}

/** How many NEW nodes `add` would introduce to `base` (for the cap check). */
export function newNodeCount(base: GraphSlice, add: GraphSlice): number {
  const have = new Set(base.nodes.map((n) => n.node_id));
  let n = 0;
  for (const node of add.nodes) if (!have.has(node.node_id)) n += 1;
  return n;
}
