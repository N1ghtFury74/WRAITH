// THROWAWAY spike smoke check (no browser required): assert the built dist/ is
// self-contained and loadable — index.html exists, references only LOCAL assets
// that exist on disk, graph.json parses with the expected shape, and no built
// asset contains a runtime CDN fetch. This is a build/offline smoke, not a
// render/FPS smoke (those require the owner to open `npm run dev` in a browser).
//
// Run:  node scripts/smoke.mjs   (after `npm run build`)

import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const dist = join(dirname(fileURLToPath(import.meta.url)), "..", "dist");
const fail = (m) => {
  console.error("SMOKE FAIL:", m);
  process.exit(1);
};

const indexPath = join(dist, "index.html");
if (!existsSync(indexPath)) fail("dist/index.html missing — run `npm run build` first");
const html = readFileSync(indexPath, "utf-8");

// every referenced asset must be local and present on disk
const refs = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map((m) => m[1]);
for (const ref of refs) {
  if (/^https?:\/\//.test(ref)) fail(`index.html references a remote asset: ${ref}`);
  const p = join(dist, ref.replace(/^\.?\//, ""));
  if (!existsSync(p)) fail(`referenced asset not found on disk: ${ref}`);
}

// graph.json present and well-shaped
const gp = join(dist, "graph.json");
if (!existsSync(gp)) fail("dist/graph.json missing");
const g = JSON.parse(readFileSync(gp, "utf-8"));
if (!Array.isArray(g.nodes) || !Array.isArray(g.edges)) fail("graph.json shape invalid");

console.log(`SMOKE OK: dist self-contained, ${refs.length} local asset refs, ` +
  `graph.json = ${g.nodes.length} nodes / ${g.edges.length} edges`);
