# WRAITH M7 UI — graph-stack confidence spike (THROWAWAY)

> **THIS IS A THROWAWAY PROTOTYPE. DO NOT BUILD ON IT.**
> Its only job is to de-risk the M7 graph stack (sigma.js + graphology, WebGL)
> on real WRAITH data before we commit to it for the production UI. It is not
> production-quality, it has no gate, and it will be deleted/rewritten when the
> real M7 app is built. Owner-approved stack per `docs/research/13-m7-ui-design-decisions.md`.

## What it does

- Loads the real **c137.local** capability graph (`public/graph.json`, dumped
  from the canonical DuckDB store — see below) into a **graphology** graph.
- Lays it out with **ForceAtlas2** (`graphology-layout-forceatlas2`).
- Renders it with **sigma.js** on **WebGL**, dark theme, nodes colored by kind.
- Supports the three spike-required interactions: **pan** (drag background),
  **zoom** (scroll wheel), **drag a node** (grab + move), and **click a node ->
  inspector side panel** showing its `id` / `label` / `kind`.
- `?bench=10000` in the URL renders a **synthetic ~10k-node / ~30k-edge** graph
  instead, and the on-screen box reports ForceAtlas2 layout time + sigma init /
  first-render time measured in *your* browser on *this* hardware.

## Run it (owner)

```bash
cd ui/spike
npm install          # build-time fetch; the registry must be reachable ONCE
npm run dev          # Vite dev server
```

Then open: **http://127.0.0.1:5173/**

- Real graph:        http://127.0.0.1:5173/
- 10k synthetic bench: http://127.0.0.1:5173/?bench=10000

Production-style build + a local static preview:

```bash
npm run build        # tsc -b && vite build  -> dist/ (self-contained)
npm run preview      # serves dist/ at http://127.0.0.1:4173/
npm run smoke        # no-browser build/offline smoke (asserts dist self-contained)
```

## Offline posture

- `npm install` / `npm ci` fetch from the npm registry **at build time only**
  (allowed). The committed `package-lock.json` makes that resolve reproducible.
- `vite build` bundles everything into `dist/` with **relative** asset refs
  (`./assets/...`). The only `http(s)://` strings in the built bundle are W3C XML
  namespace identifiers and a React error-decoder help link inside an error
  string — **none are runtime fetches**. Verified with `npm run smoke`.
- Nothing the browser loads comes from a CDN.

## How `public/graph.json` was produced

1. `python -I -m wraith case new ...` then `python -I -m wraith analyze --ntds
   <eviedence_test NTDS/ntds.dit> --system-hive ... --sam-hive ... --sysvol ...
   --output-dir <scratch>` produced the canonical DuckDB store (`canonical.duckdb`).
2. `scripts/dump_graph.py` reads the §3 node tables (`principal` / `container` /
   `gpo` / `adcs`) and the §4 `edge` table and emits
   `{nodes:[{id,label,kind}], edges:[{source,target,kind}]}`. Edges whose
   endpoints are not both modeled nodes are dropped and counted.

```bash
# regenerate (adjust paths):
python -I scripts/dump_graph.py <case>/canonical.duckdb public/graph.json
```

Dumped from c137.local: **390 nodes · 4934 graph-internal edges**
(25,369 of 30,303 store edges point at endpoints outside the modeled node set —
well-known/foreign SIDs etc. — and are dropped+counted, never silently).

## Benchmark (this hardware, `node scripts/bench_layout.mjs`)

| graph | nodes | edges | FA2 iters | layout time |
|---|---|---|---|---|
| real c137.local | 390 | 4,934 | 300 | ~0.34 s |
| synthetic | 10,000 | 30,000 | 100 | ~8.8 s |
| synthetic | 10,000 | 30,000 | 300 | ~13.6 s |

ForceAtlas2 layout is pure-JS CPU work; sigma init / first-render / interactive
FPS are WebGL and are reported in the on-screen box when you run `npm run dev`.

## Deliberate non-features (throwaway)

No server-side slicing, no TanStack Query / Zustand, no Tailwind/Radix, no app
shell, no provenance panel, no tests, no lint config — all of that belongs to
the real M7 build. Two npm advisories (esbuild/vite dev-server, dev-only) are
left as-is; irrelevant to a disposable spike.
