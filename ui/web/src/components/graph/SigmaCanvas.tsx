import EdgeCurveProgram, { indexParallelEdgesIndex } from "@sigma/edge-curve";
import { NodeBorderProgram } from "@sigma/node-border";
import { fitViewportToNodes } from "@sigma/utils";
import Graph from "graphology";
import forceAtlas2 from "graphology-layout-forceatlas2";
import noverlap from "graphology-layout-noverlap";
import { useEffect, useRef } from "react";
import Sigma from "sigma";
import type { Settings } from "sigma/settings";
import type { EdgeDisplayData, NodeDisplayData, PartialButFor } from "sigma/types";

import { curvatureFor, edgeLabelAnchor, edgeType } from "@/lib/graph/edges";
import {
  assignBlastPositions,
  assignDagPositions,
  blastRings,
  degreeMap,
  edgeColor,
  getGraphTheme,
  type GraphTheme,
  nodeColor,
  nodeSize,
} from "@/lib/graph/encoding";
import {
  isIncrementalLayout,
  jitter,
  type Pos,
  shouldShowEdgeLabel,
} from "@/lib/graph/interactions";
import { DEFAULT_LOD, lodFor, type LodState } from "@/lib/graph/lod";
import type { GraphViewProps } from "@/lib/graph/types";

/** Below this node count the client runs ForceAtlas2; above it we trust the
 * server layout (the spike showed client FA2 stalls past ~2k nodes). */
const CLIENT_LAYOUT_MAX = 2000;
const FA2_ITERATIONS = 300;
/** Always-label the N largest-degree hubs (plus Tier-0/selected/hovered). */
const TOP_DEGREE_N = 12;
/** Kinds eligible to be auto-labelled hubs. Structural kinds (Container/Base/
 *  OUContainer) are EXCLUDED: in AD they hold the highest degree (every object
 *  Contains-links to its container), so including them force-labelled the view
 *  with CN=… / DEL: / _ldap._tcp junk (owner readability complaint). They still
 *  label on hover / selection / focus. */
const HUB_LABEL_KINDS = new Set(["User", "Computer", "Group"]);
const LABEL_HALO_WIDTH = 3;
/** Edge-label halo (slightly thinner than node labels so hops stay crisp). */
const EDGE_LABEL_HALO_WIDTH = 3;
/** Bound zoom so the camera can't dive into the void or shrink to a dot. */
const MIN_CAMERA_RATIO = 0.05;
const MAX_CAMERA_RATIO = 20;

interface Focus {
  active: boolean;
  nodes: Set<string>;
}

type Isolate = { nodes: Set<string>; edges: Set<string> } | null;

/** Overlap-removal post-pass (doc 19 B.2.2): nudges nodes apart without
 * destroying the ring/cluster structure, so dots + labels stop overprinting. */
function runNoverlap(graph: Graph): void {
  noverlap.assign(graph, {
    maxIterations: 60,
    settings: { margin: 4, ratio: 1.1, gridSize: 20 },
  });
}

/** Stroke a halo under node-label glyphs so they read over edges (doc 19 P0-A.2).
 * sigma v3 has no built-in label outline — this is the fix. The halo color is the
 * OPPOSITE of the text (black in dark / white in light — doc 10 §3.1 flip). */
function drawNodeLabelHalo(
  ctx: CanvasRenderingContext2D,
  data: PartialButFor<NodeDisplayData, "x" | "y" | "size" | "label" | "color">,
  settings: Settings,
  theme: GraphTheme,
): void {
  if (!data.label) return;
  const size = settings.labelSize;
  ctx.font = `${settings.labelWeight} ${size}px ${settings.labelFont}`;
  const x = data.x + data.size + 3;
  const y = data.y + size / 3;
  ctx.lineWidth = LABEL_HALO_WIDTH;
  ctx.strokeStyle = theme.labelHalo;
  ctx.lineJoin = "round";
  ctx.strokeText(data.label, x, y);
  ctx.fillStyle = (settings.labelColor as { color: string }).color;
  ctx.fillText(data.label, x, y);
}

/** Hover label: a rounded panel (theme fill) behind the haloed glyphs. */
function drawNodeHoverHalo(
  ctx: CanvasRenderingContext2D,
  data: PartialButFor<NodeDisplayData, "x" | "y" | "size" | "label" | "color">,
  settings: Settings,
  theme: GraphTheme,
): void {
  if (!data.label) return;
  const size = settings.labelSize;
  ctx.font = `${settings.labelWeight} ${size}px ${settings.labelFont}`;
  const x = data.x + data.size + 3;
  const y = data.y + size / 3;
  const w = ctx.measureText(data.label).width;
  ctx.fillStyle = theme.hoverFill;
  const pad = 4;
  ctx.beginPath();
  ctx.roundRect(x - pad, y - size - pad / 2, w + pad * 2, size + pad * 1.5, 4);
  ctx.fill();
  drawNodeLabelHalo(ctx, data, settings, theme);
}

/**
 * Edge-label renderer with a dark halo and NO edge-length ellipsize (Round 1 A,
 * research 08 §2.2). sigma's default straight renderer fits the label to the edge
 * length and clips long relationship kinds ("AllExtendedRi…"); because labels only
 * show on a handful of focused/selected/path edges at a time, we draw the FULL
 * canonical name (BloodHound parity) at the (curved) arc midpoint, haloed so it
 * reads over edges and crossings. The anchor mirrors @sigma/edge-curve's own label
 * geometry so each parallel edge's label sits on its own arc (no overprint).
 */
function drawEdgeLabelHalo(
  ctx: CanvasRenderingContext2D,
  data: PartialButFor<EdgeDisplayData, "label" | "color" | "size">,
  sourceData: PartialButFor<NodeDisplayData, "x" | "y" | "size">,
  targetData: PartialButFor<NodeDisplayData, "x" | "y" | "size">,
  settings: Settings,
  theme: GraphTheme,
): void {
  const label = data.label;
  if (!label) return;
  const size = settings.edgeLabelSize;
  ctx.font = `${settings.edgeLabelWeight} ${size}px ${settings.edgeLabelFont}`;
  const curvature = (data as { curvature?: number }).curvature ?? 0;
  const anchor = edgeLabelAnchor(
    sourceData.x,
    sourceData.y,
    targetData.x,
    targetData.y,
    data.size ?? 1,
    curvature,
  );
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.lineWidth = EDGE_LABEL_HALO_WIDTH;
  ctx.strokeStyle = theme.labelHalo;
  ctx.lineJoin = "round";
  ctx.strokeText(label, anchor.x, anchor.y);
  const color =
    (settings.edgeLabelColor as { color?: string }).color ?? theme.edgeLabelColor;
  ctx.fillStyle = color;
  ctx.fillText(label, anchor.x, anchor.y);
  ctx.textAlign = "start";
  ctx.textBaseline = "alphabetic";
}

/**
 * Zoom-to-fit/frame the given nodes (or the whole slice). Uses @sigma/utils'
 * ``fitViewportToNodes`` (handles the camera math); a thrown/rejected fit is
 * swallowed (a transient empty graph must never crash the canvas).
 */
function fitToNodes(renderer: Sigma, ids?: string[]): void {
  const graph = renderer.getGraph();
  const nodes = ids && ids.length ? ids.filter((id) => graph.hasNode(id)) : graph.nodes();
  if (nodes.length === 0) return;
  void Promise.resolve(fitViewportToNodes(renderer, nodes, { animate: true })).catch(() => {});
}

/**
 * sigma.js + graphology WebGL canvas (the locked GraphView engine). Renders a
 * bounded slice with pan/zoom + node drag + hover-fade + click-to-select, plus
 * relationship labels on the edges (on the focused entity, path views, or the
 * "show all" toggle), click-to-expand walking, attack-path styling, single-path
 * isolation, and a right-click context-menu hook. Expansion preserves the
 * positions of already-placed nodes so the view stays stable as it grows. All
 * sigma/graphology specifics live here, behind {@link GraphViewProps}.
 */
export function SigmaCanvas({
  slice,
  selectedId,
  onSelectNode,
  onHoverNode,
  onExpandNode,
  showAllEdgeLabels = false,
  expandMode = false,
  variant = "graph",
  isolate = null,
  onNodeContextMenu,
  fitSignal = 0,
  viaNodeIds,
  resolvedTheme = "dark",
}: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const rendererRef = useRef<Sigma | null>(null);
  const graphRef = useRef<Graph | null>(null);
  const selectedRef = useRef<string | null>(selectedId);
  const focusRef = useRef<Focus>({ active: false, nodes: new Set() });
  const isolateRef = useRef<Isolate>(isolate);
  const ctxRef = useRef(onNodeContextMenu);
  ctxRef.current = onNodeContextMenu;
  const expandRef = useRef(onExpandNode);
  expandRef.current = onExpandNode;
  const showAllRef = useRef(showAllEdgeLabels);
  // Camera-ratio LOD: reducers read this to drop edge- then node-labels when the
  // camera zooms far out, and restore them on zoom-in (updated on camera `updated`).
  const lodRef = useRef<LodState>({ edgeLabels: true, nodeLabels: true, nodeLabelsAll: false });
  const viaRef = useRef<Set<string> | undefined>(viaNodeIds);
  viaRef.current = viaNodeIds;
  // Remembered node positions across slice rebuilds → stable incremental walk.
  const posRef = useRef<Map<string, Pos>>(new Map());

  // Rebuild the graph + renderer only when the slice/variant changes.
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const theme = getGraphTheme(resolvedTheme);
    const isPath = variant === "path";
    const graph = new Graph({ multi: true, type: "directed" });
    const deg = degreeMap(slice.edges);
    const useServer = slice.layout === "server";
    const highvalueIds = new Set(slice.nodes.filter((n) => n.highvalue).map((n) => n.node_id));
    const kindById = new Map(slice.nodes.map((n) => [n.node_id, n.kind] as const));
    const labelById = new Map(slice.nodes.map((n) => [n.node_id, n.label] as const));
    // Auto-labelled hubs = highest-degree PRINCIPALS only (never structural or
    // deleted "DEL:" nodes). Tier-0 (highvalue) is always labelled separately.
    const isLabelableHub = (id: string) =>
      HUB_LABEL_KINDS.has(kindById.get(id) ?? "") && !(labelById.get(id) ?? "").startsWith("DEL:");
    const topDegree = new Set(
      [...deg.entries()]
        .filter(([id]) => isLabelableHub(id))
        .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
        .slice(0, TOP_DEGREE_N)
        .map(([id]) => id),
    );
    const forceLabel = (id: string) => highvalueIds.has(id) || topDegree.has(id);

    // --- position planning (stable incremental expansion) -------------------
    // "incremental": the slice grew while keeping most previously-placed nodes
    // (a walk expand). Then we keep placed nodes put, drop new ones beside a
    // placed neighbour, and only run a gentle noverlap. Otherwise it's a fresh
    // view → full layout.
    const prevPos = posRef.current;
    const incremental = isIncrementalLayout({
      expandMode,
      variant,
      useServer,
      prevCount: prevPos.size,
      nodeCount: slice.nodes.length,
      maxNodes: CLIENT_LAYOUT_MAX,
    });
    if (!incremental) prevPos.clear();

    const positions = new Map<string, Pos>();
    slice.nodes.forEach((n) => {
      if (useServer && n.x !== null && n.y !== null) positions.set(n.node_id, { x: n.x, y: n.y });
      else if (incremental && prevPos.has(n.node_id)) positions.set(n.node_id, prevPos.get(n.node_id)!);
    });
    if (incremental) {
      const adj = new Map<string, string[]>();
      const link = (a: string, b: string) => (adj.get(a) ?? adj.set(a, []).get(a)!).push(b);
      for (const e of slice.edges) {
        link(e.source, e.target);
        link(e.target, e.source);
      }
      slice.nodes.forEach((n) => {
        if (positions.has(n.node_id)) return;
        const anchor = (adj.get(n.node_id) ?? []).find((id) => positions.has(id));
        const base = anchor ? positions.get(anchor)! : { x: 0, y: 0 };
        const j = jitter(n.node_id);
        positions.set(n.node_id, { x: base.x + j.x, y: base.y + j.y });
      });
    } else {
      slice.nodes.forEach((n, i) => {
        if (positions.has(n.node_id)) return;
        const angle = (2 * Math.PI * i) / Math.max(1, slice.nodes.length);
        positions.set(n.node_id, { x: Math.cos(angle) * 300, y: Math.sin(angle) * 300 });
      });
    }

    const via = viaRef.current;
    slice.nodes.forEach((n) => {
      const p = positions.get(n.node_id)!;
      const isVia = Boolean(via?.has(n.node_id));
      graph.addNode(n.node_id, {
        x: p.x,
        y: p.y,
        size: nodeSize(deg.get(n.node_id) ?? 0, n.highvalue),
        color: nodeColor(n, resolvedTheme),
        label: n.label,
        kind: n.kind,
        highvalue: n.highvalue,
        // Connect-the-dots intermediates render with a ghost ring (node-border
        // program) so the operator sees they were ADDED to connect, not matched.
        ...(isVia ? { type: "border", borderColor: theme.viaBorder, isVia: true } : {}),
      });
    });

    for (const e of slice.edges) {
      if (graph.hasNode(e.source) && graph.hasNode(e.target)) {
        graph.addEdgeWithKey(e.edge_id, e.source, e.target, {
          size: isPath ? theme.pathEdgeSize : theme.edgeSize,
          // AD CS / PKI edges lift into the purple family (inferred ESC composites
          // take the lighter shade, driven off confidence); every other edge keeps
          // the calm base tone so the graph stays minimal and only AD CS pops.
          color: isPath ? theme.pathEdge : edgeColor(e.kind, e.confidence, resolvedTheme),
          type: "arrow",
          kind: e.kind,
          label: e.kind,
          forceLabel: false,
        });
      }
    }

    // --- parallel-edge curving (Round 1 A) ----------------------------------
    // Index edges that share an ordered pair, then fan each bundle apart so their
    // arrowheads + labels stop overprinting. Only bundles curve (perf); singletons
    // keep the cheap built-in straight "arrow".
    indexParallelEdgesIndex(graph, {
      edgeIndexAttribute: "parallelIndex",
      edgeMaxIndexAttribute: "parallelMaxIndex",
    });
    graph.forEachEdge((edge, attrs) => {
      const idx = (attrs as { parallelIndex?: number }).parallelIndex;
      const max = (attrs as { parallelMaxIndex?: number }).parallelMaxIndex;
      if (edgeType(max) === "curve" && typeof idx === "number" && typeof max === "number") {
        graph.mergeEdgeAttributes(edge, { type: "curve", curvature: curvatureFor(idx, max) });
      }
    });

    // --- layout (doc 19 P0-B) -------------------------------------------------
    const hasTier0 = slice.nodes.some((n) => n.highvalue);
    const smallEnough = graph.order > 0 && graph.order <= CLIENT_LAYOUT_MAX;
    if (isPath && graph.order > 0 && assignDagPositions(graph)) {
      // laid out by the DAG layerer
    } else if (incremental && smallEnough) {
      // keep placed nodes; just separate the newcomers
      runNoverlap(graph);
    } else if (!useServer && variant === "graph" && hasTier0 && smallEnough) {
      assignBlastPositions(graph, blastRings(slice.nodes, slice.edges));
      runNoverlap(graph);
    } else if (!useServer && smallEnough) {
      const settings = {
        ...forceAtlas2.inferSettings(graph),
        linLogMode: true,
        outboundAttractionDistribution: true,
        gravity: 0.5,
        scalingRatio: 10,
        barnesHutOptimize: graph.order > 500,
        adjustSizes: true,
        slowDown: 2,
      };
      forceAtlas2.assign(graph, { iterations: FA2_ITERATIONS, settings });
      runNoverlap(graph);
    }

    // Remember the final positions for the next (incremental) rebuild.
    if (isPath) {
      prevPos.clear();
    } else {
      prevPos.clear();
      graph.forEachNode((id) => {
        prevPos.set(id, {
          x: graph.getNodeAttribute(id, "x") as number,
          y: graph.getNodeAttribute(id, "y") as number,
        });
      });
    }

    graphRef.current = graph;

    const renderer = new Sigma(graph, container, {
      renderEdgeLabels: true,
      defaultEdgeType: "arrow",
      defaultNodeType: "circle",
      edgeProgramClasses: { curve: EdgeCurveProgram },
      nodeProgramClasses: { border: NodeBorderProgram },
      defaultEdgeColor: isPath ? theme.pathEdge : theme.edge,
      labelColor: { color: theme.labelColor },
      labelFont: "Inter, system-ui, sans-serif",
      labelSize: 12,
      labelWeight: "600",
      labelDensity: 0.07,
      labelGridCellSize: 60,
      labelRenderedSizeThreshold: isPath ? 0 : 6,
      edgeLabelColor: { color: theme.edgeLabelColor },
      edgeLabelFont: "Inter, system-ui, sans-serif",
      edgeLabelSize: 11,
      edgeLabelWeight: "600",
      minCameraRatio: MIN_CAMERA_RATIO,
      maxCameraRatio: MAX_CAMERA_RATIO,
      zIndex: true,
      defaultDrawNodeLabel: (ctx, data, settings) => drawNodeLabelHalo(ctx, data, settings, theme),
      defaultDrawNodeHover: (ctx, data, settings) => drawNodeHoverHalo(ctx, data, settings, theme),
      defaultDrawEdgeLabel: (ctx, data, s, t, settings) =>
        drawEdgeLabelHalo(ctx, data, s, t, settings, theme),
      nodeReducer: (node: string, data): Partial<NodeDisplayData> => {
        const res: Partial<NodeDisplayData> = { ...data };
        const iso = isolateRef.current;
        const focus = focusRef.current;
        const lod = lodRef.current;
        const dimmed =
          (iso && !iso.nodes.has(node)) || (focus.active && !focus.nodes.has(node));
        if (dimmed) {
          res.color = theme.fadeNode;
          res.label = "";
          res.zIndex = 0;
        } else {
          if (highvalueIds.has(node)) {
            res.highlighted = true;
          }
          const forced = forceLabel(node) || node === selectedRef.current || focus.nodes.has(node);
          // Clean default: only forced marks (Tier-0 / principal hubs / selected /
          // focused) carry a label, so the view never overprints with structural
          // CN=… / DEL: / DNS junk. The rest are revealed only when the operator
          // zooms in close (few nodes on screen) or flips "Show all labels".
          const revealAll = showAllRef.current || lod.nodeLabelsAll;
          if (!forced && !revealAll) res.label = "";
          res.forceLabel = forced;
        }
        if (node === selectedRef.current) {
          res.zIndex = 2;
          res.size = (data.size ?? 4) * 1.5;
          res.highlighted = true;
        }
        return res;
      },
      edgeReducer: (edge: string, data): Partial<EdgeDisplayData> => {
        const iso = isolateRef.current;
        const focus = focusRef.current;
        const lod = lodRef.current;
        const [s, t] = graph.extremities(edge);
        const kind = (data as { kind?: string }).kind;
        const isolatedOn = iso ? iso.edges.has(edge) : false;
        const focusedOn = focus.nodes.has(s) && focus.nodes.has(t);
        const show =
          lod.edgeLabels &&
          shouldShowEdgeLabel({
            isolating: Boolean(iso),
            isolatedOn,
            focusActive: focus.active,
            focusedOn,
            isPath,
            showAll: showAllRef.current,
          });
        const label = show ? (kind ?? data.label) : "";
        if (iso) {
          return isolatedOn
            ? { ...data, color: theme.pathEdge, size: theme.pathEdgeSize, zIndex: 1, label, forceLabel: show }
            : { ...data, color: theme.fadeEdge, label: "", zIndex: 0 };
        }
        if (focus.active) {
          return focusedOn
            ? { ...data, color: theme.edgeFocus, size: theme.edgeSize * 1.8, zIndex: 1, label, forceLabel: show }
            : { ...data, color: theme.fadeEdge, label: "", zIndex: 0 };
        }
        return { ...data, label, forceLabel: show };
      },
    });
    rendererRef.current = renderer;

    // --- camera LOD + initial fit (Round 1 B) -------------------------------
    const camera = renderer.getCamera();
    const refreshLod = () => {
      const next = lodFor(camera.ratio, DEFAULT_LOD);
      const prev = lodRef.current;
      if (next.edgeLabels !== prev.edgeLabels || next.nodeLabels !== prev.nodeLabels) {
        lodRef.current = next;
        renderer.refresh({ skipIndexation: true });
      }
    };
    camera.on("updated", refreshLod);
    // Frame the freshly-built slice once it is laid out (base load, expand, path,
    // connector all route through a rebuild → this re-frames each time).
    const raf = requestAnimationFrame(() => fitToNodes(renderer));

    const setFocus = (node: string | null) => {
      if (node && graph.hasNode(node)) {
        focusRef.current = { active: true, nodes: new Set<string>([node, ...graph.neighbors(node)]) };
      } else {
        focusRef.current = { active: false, nodes: new Set() };
      }
      renderer.refresh({ skipIndexation: true });
    };

    // --- node drag ----------------------------------------------------------
    let dragged: string | null = null;
    let moved = false;
    renderer.on("downNode", (e) => {
      dragged = e.node;
      moved = false;
    });
    const mouse = renderer.getMouseCaptor();
    mouse.on("mousemovebody", (e) => {
      if (!dragged) return;
      moved = true;
      const pos = renderer.viewportToGraph(e);
      graph.setNodeAttribute(dragged, "x", pos.x);
      graph.setNodeAttribute(dragged, "y", pos.y);
      // keep the remembered position in sync so a later expand respects the drag
      prevPos.set(dragged, { x: pos.x, y: pos.y });
      e.preventSigmaDefault();
      e.original.preventDefault();
      e.original.stopPropagation();
    });
    mouse.on("mouseup", () => {
      dragged = null;
    });

    // --- hover + click + right-click ---------------------------------------
    renderer.on("enterNode", (e) => {
      setFocus(e.node);
      onHoverNode?.(e.node);
      container.style.cursor = "pointer";
    });
    renderer.on("leaveNode", () => {
      setFocus(selectedRef.current);
      onHoverNode?.(null);
      container.style.cursor = "default";
    });
    renderer.on("clickNode", (e) => {
      if (moved) {
        moved = false;
        return;
      }
      onSelectNode(e.node);
      expandRef.current?.(e.node);
    });
    renderer.on("clickStage", () => onSelectNode(null));
    renderer.on("rightClickNode", (e) => {
      const orig = e.event.original;
      orig.preventDefault();
      if (orig instanceof MouseEvent) {
        ctxRef.current?.(e.node, orig.clientX, orig.clientY);
      }
    });

    return () => {
      cancelAnimationFrame(raf);
      camera.off("updated", refreshLod);
      renderer.kill();
      rendererRef.current = null;
      graphRef.current = null;
    };
  }, [slice, variant, expandMode, onSelectNode, onHoverNode, resolvedTheme]);

  // Zoom-to-fit on demand (full-screen enter, "Fit" button) without a rebuild.
  useEffect(() => {
    if (fitSignal > 0 && rendererRef.current) fitToNodes(rendererRef.current);
  }, [fitSignal]);

  // React to selection changes without rebuilding the renderer.
  useEffect(() => {
    selectedRef.current = selectedId;
    const renderer = rendererRef.current;
    const graph = graphRef.current;
    if (!renderer || !graph) return;
    if (selectedId && graph.hasNode(selectedId)) {
      focusRef.current = { active: true, nodes: new Set([selectedId, ...graph.neighbors(selectedId)]) };
    } else {
      focusRef.current = { active: false, nodes: new Set() };
    }
    renderer.refresh({ skipIndexation: true });
  }, [selectedId]);

  // React to single-path isolation changes without a rebuild.
  useEffect(() => {
    isolateRef.current = isolate;
    rendererRef.current?.refresh({ skipIndexation: true });
  }, [isolate]);

  // React to the "show all edge labels" toggle without a rebuild.
  useEffect(() => {
    showAllRef.current = showAllEdgeLabels;
    rendererRef.current?.refresh({ skipIndexation: true });
  }, [showAllEdgeLabels]);

  return (
    <div
      ref={containerRef}
      className="h-full w-full"
      style={{ backgroundColor: getGraphTheme(resolvedTheme).background }}
      onContextMenu={(e) => e.preventDefault()}
    />
  );
}
