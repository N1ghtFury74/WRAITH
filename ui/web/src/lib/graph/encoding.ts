import type Graph from "graphology";
import { forEachNodeInTopologicalOrder } from "graphology-dag/topological-sort";

import type { ResolvedTheme } from "@/hooks/useTheme";
import type { GraphEdge, GraphNode } from "@/lib/api";

/**
 * Visual encoding for the capability graph. WebGL cannot read CSS variables, so
 * every color is a concrete hex/rgba selected by the resolved theme (doc 10 §3):
 * {@link getGraphTheme} returns the full {@link GraphTheme} object for `"light"`
 * or `"dark"`, mirroring the CSS token values in `index.css`. Tier-0 / high-value
 * nodes are forced to the Tier-0 red regardless of kind — the single most
 * important signal on an attack graph. Geometry (sizes, layout) is theme-independent.
 */

/** Every color/halo constant the sigma canvas needs, for one theme. */
export interface GraphTheme {
  /** Content-div backdrop behind sigma (the canvas "paper"). */
  background: string;
  /** Tier-0 / high-value node — the single most important mark. */
  tier0: string;
  /** Categorical node-kind palette (readable on this theme's canvas @ the 3:1 bar). */
  kindColors: Record<string, string>;
  /** Fallback node color for an unknown kind. */
  defaultColor: string;
  /** Base (non-path) edge tone — recedes toward the background. */
  edge: string;
  /** Base edge thickness (geometry; identical across themes). */
  edgeSize: number;
  /** Faded node/edge during hover/selection focus — toward the background. */
  fadeNode: string;
  fadeEdge: string;
  /** Lifted edge tone for the focused neighbourhood. */
  edgeFocus: string;
  /** Attack-path edge color + thickness. */
  pathEdge: string;
  pathEdgeSize: number;
  /** Node-label glyph color. */
  labelColor: string;
  /** Edge-label (relationship-name) glyph color. */
  edgeLabelColor: string;
  /**
   * Stroke under label glyphs — the readability trick that lets labels survive
   * over colored nodes/edges. MUST be the OPPOSITE of the text: black in dark,
   * white in light (doc 10 §3.1 — the critical flip).
   */
  labelHalo: string;
  /** Rounded hover-panel fill behind a hovered node's label. */
  hoverFill: string;
  /** Ghost "via" node ring (connect-the-dots intermediates ADDED to connect). */
  viaBorder: string;
  /**
   * AD CS / PKI relationship-edge hue (purple family, coherent with the
   * `EnterpriseCA`/`RootCA`/`NTAuthStore` node colors). CONFIRMED topology +
   * enrollment edges read in the saturated `adcsEdge`; INFERRED ESC composites
   * (`GraphEdge.confidence === "inferred"`) read in the lighter `adcsEdgeInferred`
   * so a composed, synthetic-tested hop is visually distinct from a confirmed base
   * edge. Both clear the 3:1 graphic bar on this theme's canvas.
   */
  adcsEdge: string;
  adcsEdgeInferred: string;
}

/**
 * The AD CS / PKI relationship-edge kinds — topology (`PublishedTo`,
 * `EnterpriseCAFor`, `RootCAFor`, `NTAuthStoreFor`, `HostsCAService`,
 * `TrustedForNTAuth`, `IssuedSignedBy`, `ExtendedByPolicy`, `OIDGroupLink`),
 * enrollment rights (`Enroll`, `AutoEnroll`), and the inferred ESC composites
 * (`ADCSESC*`, `WraithESC4TemplateControl`, `EnrollOnBehalfOf`, `GoldenCert`).
 * Mirrors `wraith/edges/adcs_topology.py` + `wraith/analysis/adcs_esc.py`.
 *
 * Membership here is only what paints an edge in the AD CS family hue; the SHADE
 * (confirmed vs inferred) is derived from `GraphEdge.confidence`, NEVER from a
 * per-kind "is inferred" list — so a new ESC kind is styled correctly the moment
 * the engine stamps it `confidence="inferred"`.
 */
export const ADCS_EDGE_KINDS: ReadonlySet<string> = new Set([
  // topology (confirmed base)
  "PublishedTo",
  "EnterpriseCAFor",
  "RootCAFor",
  "NTAuthStoreFor",
  "HostsCAService",
  "TrustedForNTAuth",
  "IssuedSignedBy",
  "ExtendedByPolicy",
  "OIDGroupLink",
  // enrollment rights (confirmed)
  "Enroll",
  "AutoEnroll",
  // inferred ESC composites
  "ADCSESC1",
  "ADCSESC3",
  "ADCSESC9",
  "ADCSESC10a",
  "ADCSESC10b",
  "ADCSESC13",
  "ADCSESC15",
  "WraithESC4TemplateControl",
  "EnrollOnBehalfOf",
  "GoldenCert",
]);

/** True when an edge kind belongs to the AD CS / PKI relationship family. */
export function isAdcsEdgeKind(kind: string): boolean {
  return ADCS_EDGE_KINDS.has(kind);
}

/** True when an edge is an inferred (composed) hop — the confidence the engine
 * stamps on every ESC composite. Pure; tolerates a null confidence. */
export function isInferredEdge(confidence: string | null | undefined): boolean {
  return confidence === "inferred";
}

const DARK_KIND_COLORS: Record<string, string> = {
  User: "#5aa9ff", // blue
  Computer: "#46d98a", // green
  Group: "#e9b949", // gold
  Domain: "#a78bff", // violet
  GPO: "#ff79c6", // magenta/pink
  OU: "#94a3b8", // slate
  OUContainer: "#94a3b8",
  Container: "#64748b", // dim slate
  Base: "#64748b",
  CertTemplate: "#4fd1c5", // teal (distinct from accent cyan)
  EnterpriseCA: "#c792ea", // purple (ADCS authorities)
  RootCA: "#c792ea",
  AIACA: "#c792ea",
  NTAuthStore: "#c792ea",
  IssuancePolicy: "#f9955a", // orange
};

/** Light node-kind palette (doc 10 §2.4) — deeper hues that clear 3:1 on white. */
const LIGHT_KIND_COLORS: Record<string, string> = {
  User: "#2563eb",
  Computer: "#059669",
  Group: "#a16207",
  Domain: "#7c3aed",
  GPO: "#db2777",
  OU: "#64748b",
  OUContainer: "#64748b",
  Container: "#808d9e",
  Base: "#808d9e",
  CertTemplate: "#0d9488",
  EnterpriseCA: "#9333ea",
  RootCA: "#9333ea",
  AIACA: "#9333ea",
  NTAuthStore: "#9333ea",
  IssuancePolicy: "#ea580c",
};

/** Dark SOC theme — the existing true-black palette. */
export const DARK_GRAPH_THEME: GraphTheme = {
  background: "#08090b",
  tier0: "#ff5d5d",
  kindColors: DARK_KIND_COLORS,
  defaultColor: "#8b93a7",
  edge: "#2b3242",
  edgeSize: 0.8,
  fadeNode: "#2a2f3a",
  fadeEdge: "#1d2230",
  edgeFocus: "#8aa0c0",
  pathEdge: "#38e0ff",
  pathEdgeSize: 2.6,
  labelColor: "#e7ebf2",
  edgeLabelColor: "#aeb9cc",
  labelHalo: "#08080a", // black — opposite of near-white label text
  hoverFill: "rgba(15,17,21,0.92)",
  viaBorder: "#8aa0c0",
  adcsEdge: "#9d6bff", // saturated purple (confirmed PKI topology/enrollment)
  adcsEdgeInferred: "#cca2ff", // lighter violet — composed/inferred ESC
};

/** Light theme — deep hues on a near-white canvas; the halo flips to white. */
export const LIGHT_GRAPH_THEME: GraphTheme = {
  background: "#fbfcfe",
  tier0: "#dc2626",
  kindColors: LIGHT_KIND_COLORS,
  defaultColor: "#64748b",
  edge: "#cbd5e1",
  edgeSize: 0.8,
  fadeNode: "#dde3ea",
  fadeEdge: "#e6ebf1",
  edgeFocus: "#64748b",
  pathEdge: "#0891b2",
  pathEdgeSize: 2.6,
  labelColor: "#0f172a",
  edgeLabelColor: "#475569",
  labelHalo: "#ffffff", // white — opposite of near-black label text (the flip)
  hoverFill: "rgba(255,255,255,0.94)",
  viaBorder: "#64748b",
  adcsEdge: "#6d28d9", // deep violet (confirmed) — clears AA on near-white
  adcsEdgeInferred: "#9d5be0", // lighter violet — composed/inferred ESC
};

/** The {@link GraphTheme} for a resolved theme. Pure; the canvas threads this in. */
export function getGraphTheme(resolved: ResolvedTheme): GraphTheme {
  return resolved === "light" ? LIGHT_GRAPH_THEME : DARK_GRAPH_THEME;
}

/** The node color for one kind (ignores Tier-0 override; see {@link nodeColor}). */
export function kindColor(kind: string, resolved: ResolvedTheme = "dark"): string {
  const theme = getGraphTheme(resolved);
  return theme.kindColors[kind] ?? theme.defaultColor;
}

/** Final node color: Tier-0 red wins, else the kind color. */
export function nodeColor(
  node: Pick<GraphNode, "kind" | "highvalue">,
  resolved: ResolvedTheme = "dark",
): string {
  return node.highvalue ? getGraphTheme(resolved).tier0 : kindColor(node.kind, resolved);
}

/**
 * Base (non-path, non-focused) color for one edge. AD CS / PKI edges are lifted
 * into the purple family so the certificate-services terrain reads as a coherent
 * group; an INFERRED composite (`confidence === "inferred"`, every ESC hop) takes
 * the lighter `adcsEdgeInferred` so "this is a composed, synthetic-tested hop" is
 * visually honest without a per-kind list. Every other edge keeps the calm base
 * tone (the graph stays minimal — only AD CS pops). Pure; the canvas threads it in.
 */
export function edgeColor(
  kind: string,
  confidence: string | null | undefined,
  resolved: ResolvedTheme = "dark",
): string {
  const theme = getGraphTheme(resolved);
  if (!isAdcsEdgeKind(kind)) return theme.edge;
  return isInferredEdge(confidence) ? theme.adcsEdgeInferred : theme.adcsEdge;
}

/** Node radius from degree (bounded so hubs don't dominate the canvas). Tier-0
 * gets a larger base so high-value reads bigger even at low degree (doc 16 P2.3). */
export function nodeSize(degree: number, highvalue: boolean): number {
  const base = 4 + Math.sqrt(degree) * 1.4;
  const size = Math.max(4, Math.min(highvalue ? base + 3 : base, 22));
  return Math.round(size * 10) / 10;
}

/** Undirected degree per node over a slice's edges (for sizing + layout hints). */
export function degreeMap(edges: GraphEdge[]): Map<string, number> {
  const deg = new Map<string, number>();
  for (const e of edges) {
    deg.set(e.source, (deg.get(e.source) ?? 0) + 1);
    deg.set(e.target, (deg.get(e.target) ?? 0) + 1);
  }
  return deg;
}

/**
 * Deterministic "blast-radius" ring assignment (doc 19 P0-B.1a): ring 0 = the
 * Tier-0 / high-value nodes; every other node sits on a ring = its undirected
 * hop-distance to the nearest Tier-0 node (BFS over the slice edges). Nodes with
 * no path to Tier-0 go to one extra outer ring. When the slice has no Tier-0, the
 * single highest-degree node roots ring 0 (fallback). O(n + e); ~instant at 400.
 */
export function blastRings(
  nodes: Array<{ node_id: string; highvalue: boolean }>,
  edges: Array<{ source: string; target: string }>,
): Map<string, number> {
  const adj = new Map<string, string[]>();
  const push = (a: string, b: string) => {
    const l = adj.get(a) ?? [];
    l.push(b);
    adj.set(a, l);
  };
  for (const e of edges) {
    push(e.source, e.target);
    push(e.target, e.source);
  }
  const ring = new Map<string, number>();
  let q: string[] = [];
  for (const n of nodes) {
    if (n.highvalue) {
      ring.set(n.node_id, 0);
      q.push(n.node_id);
    }
  }
  if (q.length === 0 && nodes.length) {
    const deg = new Map<string, number>();
    for (const e of edges) {
      deg.set(e.source, (deg.get(e.source) ?? 0) + 1);
      deg.set(e.target, (deg.get(e.target) ?? 0) + 1);
    }
    const root = [...nodes].sort(
      (a, b) => (deg.get(b.node_id) ?? 0) - (deg.get(a.node_id) ?? 0) || (a.node_id < b.node_id ? -1 : 1),
    )[0];
    ring.set(root.node_id, 0);
    q.push(root.node_id);
  }
  while (q.length) {
    const next: string[] = [];
    for (const cur of q) {
      for (const nb of (adj.get(cur) ?? []).slice().sort()) {
        if (!ring.has(nb)) {
          ring.set(nb, (ring.get(cur) ?? 0) + 1);
          next.push(nb);
        }
      }
    }
    q = next;
  }
  const maxR = ring.size ? Math.max(...ring.values()) : 0;
  for (const n of nodes) if (!ring.has(n.node_id)) ring.set(n.node_id, maxR + 1);
  return ring;
}

/** Place graph nodes on concentric rings from a {@link blastRings} map (in place). */
export function assignBlastPositions(graph: Graph, ring: Map<string, number>): void {
  const RING_STEP = 160;
  const byRing = new Map<number, string[]>();
  graph.forEachNode((id) => {
    const r = ring.get(id) ?? 0;
    (byRing.get(r) ?? byRing.set(r, []).get(r)!).push(id);
  });
  for (const [r, ids] of byRing) {
    ids.sort();
    const radius = r * RING_STEP;
    const center = r === 0 && ids.length === 1;
    ids.forEach((id, i) => {
      const a = (2 * Math.PI * i) / Math.max(1, ids.length) + r * 0.6;
      graph.setNodeAttribute(id, "x", center ? 0 : Math.cos(a) * radius);
      graph.setNodeAttribute(id, "y", center ? 0 : Math.sin(a) * radius);
    });
  }
}

/**
 * Layered left→right DAG layout for attack-path views (doc 19 B.3): each node's
 * column = longest-path-from-a-source (topological layering); rows spread within a
 * column. Sources land on the left, Tier-0 sinks on the right — the kill-chain
 * reads as a flow. Returns ``false`` if the union subgraph has a cycle (caller
 * falls back to the force layout).
 */
export function assignDagPositions(graph: Graph): boolean {
  const layer = new Map<string, number>();
  try {
    forEachNodeInTopologicalOrder(graph, (node: string) => {
      let l = 0;
      graph.forEachInNeighbor(node, (pred: string) => {
        l = Math.max(l, (layer.get(pred) ?? 0) + 1);
      });
      layer.set(node, l);
    });
  } catch {
    return false;
  }
  const byLayer = new Map<number, string[]>();
  graph.forEachNode((id) => {
    const l = layer.get(id) ?? 0;
    (byLayer.get(l) ?? byLayer.set(l, []).get(l)!).push(id);
  });
  const COL = 240;
  const ROW = 90;
  for (const [l, ids] of byLayer) {
    ids.sort();
    ids.forEach((id, i) => {
      graph.setNodeAttribute(id, "x", l * COL);
      graph.setNodeAttribute(id, "y", (i - (ids.length - 1) / 2) * ROW);
    });
  }
  return true;
}

/** Legend entries actually present in a slice (deterministic, sorted by kind). */
export function legendForSlice(
  nodes: GraphNode[],
  resolved: ResolvedTheme = "dark",
): Array<{ kind: string; color: string }> {
  const kinds = new Set<string>();
  let hasTier0 = false;
  for (const n of nodes) {
    if (n.highvalue) hasTier0 = true;
    else kinds.add(n.kind);
  }
  const entries = [...kinds].sort().map((kind) => ({ kind, color: kindColor(kind, resolved) }));
  if (hasTier0) entries.unshift({ kind: "Tier-0 / high value", color: getGraphTheme(resolved).tier0 });
  return entries;
}

/** One AD CS relationship-legend row (a line swatch, not a node dot). */
export interface EdgeLegendEntry {
  label: string;
  color: string;
  /** True = the `confidence="inferred"` (ESC composite) group — flagged synthetic. */
  inferred: boolean;
}

/**
 * The AD CS / PKI relationship-legend rows actually present in a slice: a
 * "confirmed topology" row when any confirmed AD CS edge is drawn, and an
 * "inferred ESC (synthetic)" row when any inferred ESC composite is drawn. Returns
 * `[]` when the slice carries no AD CS edges (the legend then shows node kinds
 * only). Deterministic; confirmed leads inferred.
 */
export function edgeLegendForSlice(
  edges: Array<Pick<GraphEdge, "kind" | "confidence">>,
  resolved: ResolvedTheme = "dark",
): EdgeLegendEntry[] {
  let hasConfirmed = false;
  let hasInferred = false;
  for (const e of edges) {
    if (!isAdcsEdgeKind(e.kind)) continue;
    if (isInferredEdge(e.confidence)) hasInferred = true;
    else hasConfirmed = true;
  }
  const theme = getGraphTheme(resolved);
  const out: EdgeLegendEntry[] = [];
  if (hasConfirmed) out.push({ label: "AD CS topology", color: theme.adcsEdge, inferred: false });
  if (hasInferred)
    out.push({ label: "AD CS ESC (inferred)", color: theme.adcsEdgeInferred, inferred: true });
  return out;
}
