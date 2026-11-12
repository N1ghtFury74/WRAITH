// THROWAWAY spike benchmark: measure graphology ForceAtlas2 layout time in Node
// (pure-JS CPU work, no DOM) for the real c137.local graph and a synthetic
// ~10k-node / ~30k-edge graph on this hardware. sigma init / first-render /
// interactive FPS require a WebGL/DOM context and are read from the in-app
// on-screen timing box when the owner runs `npm run dev`.
//
// Run:  node scripts/bench_layout.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import Graph from "graphology";
import forceAtlas2 from "graphology-layout-forceatlas2";

const here = dirname(fileURLToPath(import.meta.url));

function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function buildReal() {
  const raw = JSON.parse(readFileSync(join(here, "..", "public", "graph.json"), "utf-8"));
  const g = new Graph({ multi: true, type: "directed" });
  const rand = rng(1337);
  for (const n of raw.nodes) g.addNode(n.id, { x: rand() * 1000, y: rand() * 1000, size: 4 });
  for (const e of raw.edges) if (g.hasNode(e.source) && g.hasNode(e.target)) g.addEdge(e.source, e.target);
  return g;
}

function synth(n, m) {
  const g = new Graph({ multi: true, type: "directed" });
  const rand = rng(424242);
  for (let i = 0; i < n; i++) g.addNode(`n${i}`, { x: rand() * 2000, y: rand() * 2000, size: 3 });
  for (let i = 0; i < m; i++) {
    const s = Math.floor(rand() * n);
    let t = (s + 1 + Math.floor(rand() * Math.min(50, n - 1))) % n;
    if (t === s) t = (t + 1) % n;
    g.addEdge(`n${s}`, `n${t}`);
  }
  return g;
}

function bench(name, g, iterations) {
  const settings = forceAtlas2.inferSettings(g);
  const t0 = performance.now();
  forceAtlas2.assign(g, { iterations, settings });
  const ms = performance.now() - t0;
  console.log(
    `${name.padEnd(28)} ${String(g.order).padStart(6)} nodes ${String(g.size).padStart(6)} edges ` +
      `${String(iterations).padStart(5)} iters -> ${ms.toFixed(1).padStart(9)} ms`,
  );
}

console.log("ForceAtlas2 layout benchmark (Node, pure JS) — " + new Date().toISOString());
bench("real c137.local", buildReal(), 300);
bench("synthetic 10k / 30k", synth(10000, 30000), 100);
bench("synthetic 10k / 30k", synth(10000, 30000), 300);
