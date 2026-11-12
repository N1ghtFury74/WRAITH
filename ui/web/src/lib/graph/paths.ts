import type { AttackPath, GraphEdge, GraphNode, GraphSlice, PathEdge, PathResult } from "@/lib/api";

/**
 * Stable key for a path edge. The backend usually supplies `edge_id`; when it is
 * null we synthesize a deterministic key so the union subgraph and single-path
 * isolation agree on edge identity (SigmaCanvas adds edges under this key).
 */
export function edgeKey(e: PathEdge): string {
  return e.edge_id ?? `${e.source}→${e.target}:${e.kind}`;
}

/**
 * Build the union subgraph of all returned paths (design §7.4): every path
 * node + edge, deduped. Path target sinks are marked high-value so they keep the
 * Tier-0 red marking on the canvas (PathResult NodeRefs carry no tier, so the
 * target set is the authoritative sink marker).
 */
export function pathUnionSlice(result: PathResult): GraphSlice {
  const targets = new Set<string>([
    ...result.target_node_ids,
    ...result.paths.map((p) => p.target_node_id),
  ]);
  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  for (const p of result.paths) {
    for (const n of p.nodes) {
      if (!nodes.has(n.node_id)) {
        const isTarget = targets.has(n.node_id);
        nodes.set(n.node_id, {
          node_id: n.node_id,
          kind: n.kind,
          label: n.label,
          object_sid: null,
          tier: isTarget ? 0 : null,
          highvalue: isTarget,
          x: null,
          y: null,
        });
      }
    }
    for (const e of p.edges) {
      const id = edgeKey(e);
      if (!edges.has(id)) {
        edges.set(id, {
          edge_id: id,
          kind: e.kind,
          source: e.source,
          target: e.target,
          confidence: null,
          is_inherited: null,
        });
      }
    }
  }
  const nodeArr = [...nodes.values()];
  const edgeArr = [...edges.values()];
  return {
    nodes: nodeArr,
    edges: edgeArr,
    total_matched: nodeArr.length,
    returned: nodeArr.length,
    truncated: false,
    layout: "none",
    seed_node_ids: [],
    depth: 0,
  };
}

/** Node + edge key sets for one path (drives single-path isolation highlight). */
export function pathIsolation(p: AttackPath): { nodes: Set<string>; edges: Set<string> } {
  return {
    nodes: new Set(p.nodes.map((n) => n.node_id)),
    edges: new Set(p.edges.map(edgeKey)),
  };
}

/** Readable hop segments for the step list: "A —Kind→ B —Kind→ C". */
export function pathSegments(p: AttackPath): Array<{ from: string; kind: string; to: string }> {
  return p.edges.map((e, i) => ({
    from: p.nodes[i]?.label ?? e.source,
    kind: e.kind,
    to: p.nodes[i + 1]?.label ?? e.target,
  }));
}
