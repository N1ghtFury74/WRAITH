import { useEffect, useRef } from "react";
import Graph from "graphology";
import forceAtlas2 from "graphology-layout-forceatlas2";
import Sigma from "sigma";

export interface Timings {
  nodes: number;
  edges: number;
  layoutMs: number;
  initMs: number;
}

interface Props {
  graph: Graph;
  fa2Iterations: number;
  onSelect: (attrs: Record<string, unknown> | null) => void;
  onTimings: (t: Timings) => void;
}

/**
 * Mounts a sigma.js (WebGL) renderer over a graphology graph. Runs ForceAtlas2
 * to position nodes (timed), reports init/first-render time, and wires the three
 * spike-required interactions: pan/zoom (sigma built-ins), node DRAG, and
 * click-to-inspect.
 */
export default function GraphView({ graph, fa2Iterations, onSelect, onTimings }: Props) {
  const containerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // --- ForceAtlas2 layout (timed) ---
    const settings = forceAtlas2.inferSettings(graph);
    const t0 = performance.now();
    forceAtlas2.assign(graph, { iterations: fa2Iterations, settings });
    const layoutMs = performance.now() - t0;

    // --- sigma init / first render (timed) ---
    const t1 = performance.now();
    const renderer = new Sigma(graph, container, {
      renderEdgeLabels: false,
      defaultEdgeColor: "#2b3545",
      labelColor: { color: "#d7dde8" },
      labelDensity: 0.6,
      labelRenderedSizeThreshold: 8,
      zIndex: true,
    });
    renderer.refresh();
    const initMs = performance.now() - t1;

    onTimings({
      nodes: graph.order,
      edges: graph.size,
      layoutMs: Math.round(layoutMs),
      initMs: Math.round(initMs),
    });

    // --- node DRAG (sigma events + graphology mutation) ---
    let draggedNode: string | null = null;
    let dragging = false;
    let moved = false;

    renderer.on("downNode", (e) => {
      dragging = true;
      moved = false;
      draggedNode = e.node;
      graph.setNodeAttribute(draggedNode, "highlighted", true);
    });

    const mouse = renderer.getMouseCaptor();
    mouse.on("mousemovebody", (e) => {
      if (!dragging || !draggedNode) return;
      moved = true;
      const pos = renderer.viewportToGraph(e);
      graph.setNodeAttribute(draggedNode, "x", pos.x);
      graph.setNodeAttribute(draggedNode, "y", pos.y);
      // stop the camera from panning while we drag a node
      e.preventSigmaDefault();
      e.original.preventDefault();
      e.original.stopPropagation();
    });

    const endDrag = () => {
      if (draggedNode) graph.removeNodeAttribute(draggedNode, "highlighted");
      dragging = false;
      draggedNode = null;
    };
    mouse.on("mouseup", endDrag);

    // --- click-to-inspect (ignore the click that ends a drag) ---
    renderer.on("clickNode", (e) => {
      if (moved) {
        moved = false;
        return;
      }
      onSelect({ id: e.node, ...graph.getNodeAttributes(e.node) });
    });
    renderer.on("clickStage", () => onSelect(null));

    return () => {
      renderer.kill();
    };
    // Rebuild only when the graph instance itself changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph]);

  return <div id="sigma" ref={containerRef} />;
}
