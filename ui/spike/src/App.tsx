import { useEffect, useMemo, useState } from "react";
import type Graph from "graphology";
import GraphView, { type Timings } from "./GraphView";
import { buildGraph, synthGraph, type RawGraph } from "./graph";
import { colorForKind, kindsOf } from "./colors";

type Selected = Record<string, unknown> | null;

// `?bench=10000` (or any N) renders a synthetic ~N-node / ~3N-edge graph for the
// performance benchmark instead of the real c137.local export.
function benchParam(): number | null {
  const v = new URLSearchParams(window.location.search).get("bench");
  if (!v) return null;
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : 10000;
}

export default function App() {
  const bench = benchParam();
  const [graph, setGraph] = useState<Graph | null>(null);
  const [selected, setSelected] = useState<Selected>(null);
  const [timings, setTimings] = useState<Timings | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (bench !== null) {
      setGraph(synthGraph(bench, bench * 3));
      return;
    }
    fetch("./graph.json")
      .then((r) => {
        if (!r.ok) throw new Error(`graph.json HTTP ${r.status}`);
        return r.json() as Promise<RawGraph>;
      })
      .then((raw) => setGraph(buildGraph(raw)))
      .catch((e: unknown) => setError(String(e)));
  }, [bench]);

  // Fewer FA2 iterations for the big synthetic graph so layout stays measurable.
  const iterations = bench !== null ? 100 : 300;

  const legendKinds = useMemo(() => {
    if (!graph) return [];
    const ks: string[] = [];
    graph.forEachNode((_n, a) => ks.push(a.kind as string));
    return kindsOf(ks);
  }, [graph]);

  return (
    <div className="app">
      <div className="canvas">
        <div className="topbar">
          <span className="brand">WRAITH</span>
          <span className="muted">M7 graph spike (throwaway)</span>
          <span className="muted">
            {bench !== null ? `synthetic bench ~${bench} nodes` : "case: c137.local"}
          </span>
          {graph && (
            <span className="muted">
              {graph.order} nodes / {graph.size} edges
            </span>
          )}
        </div>

        {error && <div className="bench">ERROR: {error}</div>}
        {graph && (
          <GraphView
            graph={graph}
            fa2Iterations={iterations}
            onSelect={setSelected}
            onTimings={setTimings}
          />
        )}

        {timings && (
          <div className="bench">
            {`FA2 layout (${timings.nodes}n/${timings.edges}e, ${iterations} iters): ${timings.layoutMs} ms\n` +
              `sigma init + first render:            ${timings.initMs} ms`}
          </div>
        )}
      </div>

      <div className="sidepanel">
        <h2>Inspector</h2>
        {selected ? (
          <>
            <div className="kv">
              <div className="k">kind</div>
              <div className="v">
                <span
                  className="swatch"
                  style={{ background: colorForKind(String(selected.kind)) }}
                />
                {String(selected.kind)}
              </div>
            </div>
            <div className="kv">
              <div className="k">label</div>
              <div className="v">{String(selected.label)}</div>
            </div>
            <div className="kv">
              <div className="k">id (node_id)</div>
              <div className="v">{String(selected.id)}</div>
            </div>
          </>
        ) : (
          <div className="muted">Click a node to inspect it.</div>
        )}

        <div className="legend">
          <h2>Legend</h2>
          {legendKinds.map((k) => (
            <div key={k}>
              <span className="swatch" style={{ background: colorForKind(k) }} />
              {k}
            </div>
          ))}
        </div>

        <div className="hint">
          Pan: drag the background · Zoom: scroll wheel · Move a node: drag it ·
          Inspect: click a node. This is a disposable spike, not the production UI.
        </div>
      </div>
    </div>
  );
}
