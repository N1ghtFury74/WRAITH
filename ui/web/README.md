# WRAITH Web UI (`ui/web`) — FE-1

Production React/Vite SPA for WRAITH M7: the app shell + the **operate-everything**
case / upload / coverage / analyze flow. Maintainer documentation.

> Stack is LOCKED (`docs/research/13-m7-ui-design-decisions.md`, memory
> `m7-stack-decisions`): React + TypeScript + Vite, Tailwind + Radix/shadcn,
> TanStack Query + Zustand, dark-first. The sigma.js/graphology graph canvas is
> FE-2 — this build ships a routed placeholder slot for it, not the canvas.

## Offline guarantee (non-negotiable)

Everything the browser loads is vendored by the Vite build: no CDN, no Google
Fonts link, no analytics. Fonts (Inter, JetBrains Mono) are self-hosted `woff2`
bundled from the `@fontsource/*` npm packages. The only network the shipped UI
touches at runtime is the **same-origin WRAITH API** (`/api/v1/...` — a relative
path with no scheme/host).

`npm install` (build-time, on a connected machine) is allowed; the committed
`package-lock.json` pins every dependency for a reproducible, air-gappable build.

### Offline check (CI-style gate)

```bash
npm run build          # produce dist/
npm run check:offline  # scripts/check-offline.mjs — FAILS on any external runtime URL
# or both at once:
npm run verify
```

`check-offline.mjs` greps the built `dist/` for absolute `http(s)://` URLs and
fails the build on any match that is not on a tiny allowlist of inert embedded
strings (W3C XML namespaces, React/react-router console-warning doc links,
localhost/127.0.0.1). Same-origin API calls use relative paths and so never
match. Keep the allowlist minimal; a new entry must be a provably non-fetched
string literal.

## Run it on localhost

### Mode A — dev with API proxy (fast iteration)

Two terminals:

```bash
# 1) WRAITH API (uvicorn) — a case workspace, analyzed or not, on the default port
python -I -m wraith serve --cases-root ./cases --case-id <id>   # binds 127.0.0.1:8713

# 2) Vite dev server (this directory)
cd ui/web
npm install        # once, build-time fetch allowed; vendored by package-lock.json
npm run dev        # http://127.0.0.1:5173
```

Open **http://127.0.0.1:5173/**. The dev server proxies `/api` (including the
`/api/v1/ws/progress` WebSocket) to `http://127.0.0.1:8713`, so the client makes
the same same-origin requests it will in production (no CORS, no hard-coded host).
Override the backend target with `WRAITH_API_TARGET` if uvicorn runs elsewhere.

> Note: `wraith serve` today opens a single analyzed case read-only. The FE-1
> ingest flow (`POST /cases`, upload, `/analyze`) talks to the writable
> case/ingest router, which is mounted by the same app. Point `serve` at any
> existing case; create/select other cases from the UI.

### Mode B — integrated, served by FastAPI (offline, single origin)

```bash
cd ui/web
npm run build      # emits ui/web/dist/

# then start the API as usual; it auto-mounts the SPA if dist/ exists
python -I -m wraith serve --cases-root ./cases --case-id <id>
```

Open **http://127.0.0.1:8713/**. FastAPI serves the built SPA at `/` with an
history-API fallback (deep links like `/case/<id>/graph` load `index.html`), the
API stays under `/api/v1`, and `/api/*` never falls through to the SPA. The mount
is additive and **optional**: if `dist/` is absent the app is API-only and the M7
gate is unaffected. Override the served directory with `WRAITH_UI_DIST`.

## Scripts

| script | what it does |
|---|---|
| `npm run dev` | Vite dev server (`127.0.0.1:5173`) with `/api` proxy |
| `npm run build` | `tsc -b` type-check + `vite build` → `dist/` |
| `npm run preview` | Serve the built `dist/` locally (no API proxy) |
| `npm run lint` | ESLint (TS strict, no `any`) |
| `npm run check:offline` | Fail the build on any external runtime URL in `dist/` |
| `npm run verify` | `build` then `check:offline` |

## Layout

```
src/
  main.tsx                 entry (QueryClient + RouterProvider)
  router.tsx               routes (AppShell + case-scoped pages)
  index.css                theme tokens + self-hosted font imports
  lib/
    api.ts                 THE typed API client (mirrors wraith/api + case models) + WS url
    reasons.ts             typed backend reason -> operator-facing message
    utils.ts               cn(), formatBytes(), shortSha()
  store/
    cases.ts               localStorage-backed known-cases list (see decision below)
    run.ts                 shared live analyze-run state (status bar, badges)
  hooks/useAnalyzeRun.ts   POST /analyze + stream /ws/progress into the run store
  components/
    shell/                 TopBar, Sidebar (module rail), StatusBar, AppShell, nav
    ui/                    button, card, badge, progress, input, label, states (shadcn-style)
  lib/graph/
    encoding.ts            node-kind palette, Tier-0 red, sizing, legend (WebGL hex, mirrors tokens)
    types.ts               GraphViewProps — the thin, swappable GraphView contract (doc 13 §1)
  components/graph/
    SigmaCanvas.tsx        sigma.js + graphology WebGL canvas (the GraphView impl): drag/pan/zoom/hover/select
    FilterRail.tsx         node/edge-kind toggles, Tier-0-only, seed search + depth
    Inspector.tsx          right-hand compact node inspector (identity, UAC, edges, risk, provenance)
    Legend.tsx             kinds present in the current slice
  routes/
    CasesPage.tsx          create / attach / select a case
    IngestPage.tsx         the operate-everything flow (catalog + coverage + analyze)
    ingest/                UploadTile, CoveragePanel, AnalyzePanel
    GraphPage.tsx          FE-2 capability graph (filter rail + canvas + inspector), READY-gated
    placeholders.tsx       Dossiers / Risk / Baselining (reserved)
scripts/check-offline.mjs  offline gate
```

## FE-2 — the capability graph (`/case/:caseId/graph`)

sigma.js + graphology WebGL canvas (the locked engine). Consumes
`POST /api/v1/graph/slice?case_id=` and renders a bounded slice: server
precomputes node x/y at/above 250 nodes (`layout:"server"`), otherwise the client
runs ForceAtlas2 (skipped above ~2k nodes — the spike showed it stalls). Pan,
zoom, **drag nodes**, hover-fade non-neighbours, click → right inspector
(`/nodes/{id}?case_id=`), click empty → deselect. Left rail: node/edge-kind
toggles + counts (from `/summary`), Tier-0-only, and a seed search
(`/search?case_id=`) with a depth control. Honest truncation line
("returned / total_matched — refine filters") from the slice. READY-gated off a
`/summary` probe (409/400 → "run analysis"; success → load the slice). The
renderer is isolated behind `lib/graph/types.ts#GraphViewProps`, so a cytoscape
WebGL impl of the same props is a drop-in swap (doc 13's GraphView interface).

Graph deps (pinned, MIT, vendored): `sigma 3.0.2`, `graphology 0.26.0`,
`graphology-layout-forceatlas2 0.10.1`, `graphology-types 0.24.8` (dev).

## Attack-path analysis ("road to Domain Admin", design doc 15)

The Graph route is the analysis workbench:

- **Default view** = `GET /graph/default` (edge-rich Tier-0 neighborhood). Node/edge
  kind + Tier-0 + seed are opt-in *refinements* (then it uses `POST /graph/slice`);
  they are never the initial load (fixes the "nodes but 0 edges" bug).
- **Analysis panel** (left rail, top) lists `GET /analysis/queries` as one-click
  buttons with live `source_count`; unsupported entries are greyed with the `reason`
  tooltip and `synthetic-only` carries a caveat badge. `path` results render as the
  highlighted union subgraph + a hop-by-hop step list; `set` results render as the
  node collection with `total_matched`/`truncated`.
- **Right-click a node** → context menu: shortest paths to Tier Zero (outbound),
  who-can-reach-this (inbound), set as path start/end, expand neighbors, open dossier.
- **Node-to-node** form (left rail) with a swap control → `POST /paths`.
- **Path rendering:** union subgraph on the canvas (path edges cyan + thick, Tier-0
  sinks red); the `PathResultPanel` lists each path, click a row to isolate it (dims
  the rest). Honest truncation surfaced verbatim: `paths_found`/`truncated`,
  `over_budget_targets`, `unreachable_targets`, and `counted_gaps`.
- The sigma renderer stays behind `lib/graph/types.ts#GraphViewProps` (now also
  carrying `variant`/`isolate`/`onNodeContextMenu`) — still a swappable GraphView.

New API client methods: `graphDefault`, `listQueries`, `runQuery`, `paths`,
`neighbors`. No new npm deps for this slice.

## Design decisions not spelled out by doc 13

- **Case list is client-side (localStorage).** The API exposes case *creation*
  (`POST /cases`) and per-case reads, but no endpoint listing every workspace on
  disk. The authoritative "which case" is therefore the `case_id` in the route;
  `store/cases.ts` is the convenience list powering the top-bar selector and the
  READY badges. A CLI-created case is opened via **Attach existing** (validated
  against `GET /catalog`; 404 → unknown). If a server-side case-listing endpoint
  lands later, swap this store for a query with no UI reshape.
- **Upload progress uses `XMLHttpRequest`, not `fetch`.** Only XHR exposes upload
  progress events, which the per-file bar needs. Still same-origin.
- **Multi/host kinds stage before upload.** `member_sam` / `additional_dc` require
  a `host_label`, so the tile stages the chosen file and enables Upload once the
  label is set; `member_sam` also offers an optional companion SYSTEM hive.
- **Pass detail polls `GET /runs/{id}`** alongside the WS stream: the WS drives the
  headline `%`/current-pass/state; the poll fills the per-pass checklist and the
  final node/edge/export result summary (the WS `done` event omits those).
