import type { ResolvedTheme } from "@/hooks/useTheme";
import type { GraphSlice } from "@/lib/api";

/**
 * The thin, swappable GraphView contract (doc 13 §1 "GraphView interface").
 *
 * The capability-graph canvas is consumed only through these props, so the
 * concrete renderer is replaceable: FE-2 ships {@link ../../components/graph/SigmaCanvas}
 * (sigma.js + graphology, WebGL — the locked engine), and a cytoscape.js (WebGL)
 * implementation of the SAME props could be dropped in behind a feature flag
 * without touching the page, filters, or inspector. Keep all renderer-specific
 * code (sigma events, graphology mutation, reducers) inside the implementation.
 */
export interface GraphViewProps {
  /** The bounded slice to render. A new object identity triggers a rebuild. */
  slice: GraphSlice;
  /** Currently-selected node id (drives highlight + the inspector), or null. */
  selectedId: string | null;
  /** Click a node -> id; click empty space -> null. */
  onSelectNode: (nodeId: string | null) => void;
  /** Hover enter/leave (optional; used for status/affordances). */
  onHoverNode?: (nodeId: string | null) => void;
  /** "path" styles all edges as attack-path edges (bright, thick). Default "graph". */
  variant?: "graph" | "path";
  /** When set, dim everything outside these node/edge keys (single-path isolation). */
  isolate?: { nodes: Set<string>; edges: Set<string> } | null;
  /** Right-click a node -> (nodeId, screen x, screen y) for a context menu. */
  onNodeContextMenu?: (nodeId: string, x: number, y: number) => void;
  /** Click a node -> pull its neighbours into the canvas (walk the graph). The
   * page fetches + merges; the canvas preserves placed nodes so the view is stable. */
  onExpandNode?: (nodeId: string) => void;
  /** Force every edge's relationship label on (toolbar "Show all labels"). When
   * false, labels show only on the focused/selected node's edges + path views. */
  showAllEdgeLabels?: boolean;
  /** True when this slice change is an interactive walk expansion (so the canvas
   * keeps already-placed nodes put and only settles the newcomers). False for a
   * fresh view (first load, filter change, reset, analysis) → full re-layout. */
  expandMode?: boolean;
  /** Bump this number to trigger a zoom-to-fit/frame (full-screen enter, "Fit"
   * button). The canvas also auto-fits after every (re)build. */
  fitSignal?: number;
  /** Node ids inserted to CONNECT the retained set (connect-the-dots): styled as
   * distinct ghost "via" nodes so the operator sees they weren't filter matches. */
  viaNodeIds?: Set<string>;
  /** Resolved theme ("light"|"dark") driving the WebGL color palette (doc 10 §3).
   * A change rebuilds the canvas so every node/edge/label/halo re-selects. */
  resolvedTheme?: ResolvedTheme;
}
