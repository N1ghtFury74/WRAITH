import Graph from "graphology";
import { colorForKind } from "./colors";

export interface RawNode {
  id: string;
  label: string;
  kind: string;
}
export interface RawEdge {
  source: string;
  target: string;
  kind: string;
}
export interface RawGraph {
  nodes: RawNode[];
  edges: RawEdge[];
}

// Deterministic PRNG so layouts/synthetic graphs are reproducible (mulberry32).
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Build a graphology graph from the dumped {nodes,edges} JSON.
 * Assigns a color-by-kind and a seeded random initial position (ForceAtlas2
 * needs non-coincident starting coordinates). Duplicate/parallel edges are
 * tolerated with a multigraph so nothing is silently dropped.
 */
export function buildGraph(raw: RawGraph): Graph {
  const graph = new Graph({ multi: true, type: "directed" });
  const rand = rng(1337);
  for (const n of raw.nodes) {
    graph.addNode(n.id, {
      label: n.label,
      kind: n.kind,
      color: colorForKind(n.kind),
      size: 4,
      x: rand() * 1000,
      y: rand() * 1000,
    });
  }
  let skipped = 0;
  for (const e of raw.edges) {
    if (!graph.hasNode(e.source) || !graph.hasNode(e.target)) {
      skipped++;
      continue;
    }
    graph.addEdge(e.source, e.target, {
      kind: e.kind,
      size: 0.6,
      color: "#2b3545",
    });
  }
  if (skipped) console.warn(`buildGraph: skipped ${skipped} edges with missing endpoints`);
  return graph;
}

const SYNTH_KINDS = ["User", "Computer", "Group", "Container", "GPO", "OU", "Domain"];

/**
 * Generate a synthetic graph of ~n nodes / ~m edges for the performance
 * benchmark. Seeded for determinism. Produces a loosely-clustered structure so
 * ForceAtlas2 has something realistic to lay out.
 */
export function synthGraph(n: number, m: number): Graph {
  const graph = new Graph({ multi: true, type: "directed" });
  const rand = rng(424242);
  for (let i = 0; i < n; i++) {
    const kind = SYNTH_KINDS[Math.floor(rand() * SYNTH_KINDS.length)];
    graph.addNode(`n${i}`, {
      label: `node-${i}`,
      kind,
      color: colorForKind(kind),
      size: 3,
      x: rand() * 2000,
      y: rand() * 2000,
    });
  }
  for (let i = 0; i < m; i++) {
    const s = Math.floor(rand() * n);
    // bias target near source to create locality/clusters
    let t = (s + 1 + Math.floor(rand() * Math.min(50, n - 1))) % n;
    if (t === s) t = (t + 1) % n;
    graph.addEdge(`n${s}`, `n${t}`, { size: 0.5, color: "#2b3545" });
  }
  return graph;
}
