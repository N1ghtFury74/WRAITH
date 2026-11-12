import type { ConnectorResult, GraphEdge, GraphNode, GraphSlice } from "@/lib/api";
import { edgeKey } from "@/lib/graph/paths";

/**
 * Pure rendering logic for the connect-the-dots reveal (Round 1 C).
 *
 * The backend returns the two lanes already classified (control first, then scope);
 * these helpers turn that result into a path-variant slice for the canvas, mark the
 * intermediate "via" nodes that were ADDED to connect (so they can be ghost-ringed),
 * and provide a lane classifier that MIRRORS the backend contract (doc 09 §1.5) so
 * the UI's lane handling is independently testable.
 */

/** Structural "applies-to"/containment edge kinds (the scope lane). */
export const SCOPE_EDGE_KINDS = new Set(["Contains", "GPLink"]);
/** Principal node kinds a GPO scope chain may terminate at. */
export const PRINCIPAL_KINDS = new Set(["User", "Computer", "Group"]);

export type ConnectorLane = "control" | "scope" | "noise";

/**
 * Classify a chain from its hop kinds + endpoint kinds, mirroring the backend:
 *  - no structural hop → ``control`` (real capability);
 *  - a structural hop present AND ``GPO → … → principal`` → ``scope`` (application);
 *  - otherwise (pure containment / co-location) → ``noise`` (suppressed).
 */
export function classifyConnectorLane(
  hopKinds: readonly string[],
  startKind: string,
  endKind: string,
): ConnectorLane {
  const hasStructural = hopKinds.some((k) => SCOPE_EDGE_KINDS.has(k));
  if (!hasStructural) return "control";
  if (startKind === "GPO" && PRINCIPAL_KINDS.has(endKind)) return "scope";
  return "noise";
}

/** Rank for ordering lanes (control before scope); matches backend ranking. */
export function laneRank(lane: "control" | "scope"): number {
  return lane === "control" ? 0 : 1;
}

/**
 * Build the union slice of all connector chains for the path-variant canvas: every
 * chain node + hop, deduped. Target sinks are NOT force-marked high-value here (the
 * connector is not an attack-to-Tier-0 result); the via-node styling comes from
 * {@link viaNodeSet}. Provenance-light edges (connector hops) keep their kind label.
 */
export function connectorUnionSlice(result: ConnectorResult): GraphSlice {
  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  const retained = new Set(result.retained_node_ids);
  for (const p of result.paths) {
    for (const n of p.nodes) {
      if (!nodes.has(n.node_id)) {
        nodes.set(n.node_id, {
          node_id: n.node_id,
          kind: n.kind,
          label: n.label,
          object_sid: null,
          tier: n.is_tier0 ? 0 : null,
          highvalue: Boolean(n.is_tier0) && retained.has(n.node_id),
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
    truncated: result.truncated,
    layout: "none",
    seed_node_ids: [],
    depth: 0,
  };
}

/** The set of intermediate "via" node ids (ADDED to connect — ghost-ringed). */
export function viaNodeSet(result: ConnectorResult): Set<string> {
  return new Set(result.via_node_ids);
}
