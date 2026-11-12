// WRAITH offline-guarantee check (CLAUDE.md non-negotiable).
//
// Scans the built `dist/` tree for absolute `http(s)://` URLs. ANY match that is
// not on the explicit allowlist FAILS the build — WRAITH must load nothing from a
// CDN or external origin at runtime; the only network the shipped UI may touch is
// the same-origin WRAITH API (a relative `/api/...` path, which carries no
// scheme and so never matches here).
//
// The allowlist is deliberately tiny and covers only inert *string literals* that
// bundlers/libraries embed and the browser never fetches:
//   - XML/SVG namespace identifiers (w3.org) used as attribute values,
//   - React's error-decoder help link (react.dev / reactjs.org) inside a thrown
//     Error message string,
//   - localhost / 127.0.0.1 (a dev target, never shipped as a live fetch).
// Everything else is treated as a potential runtime egress and fails loudly.
//
// Run:  node scripts/check-offline.mjs   (after `npm run build`)

import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { dirname, extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, "..", "dist");

/** Hosts/prefixes that are inert embedded strings, never runtime fetches. */
const ALLOW = [
  "http://www.w3.org/",
  "https://www.w3.org/",
  "http://localhost",
  "https://localhost",
  "http://127.0.0.1",
  "https://127.0.0.1",
  "https://reactjs.org/docs/error-decoder",
  "https://react.dev/errors",
  // react-router v6 embeds doc links in console deprecation-warning strings
  // (future flags). Inert text in a console.warn, never fetched.
  "https://reactrouter.com/",
  // Radix UI embeds an a11y docs link in a dev-only console warning template
  // string (e.g. missing DialogTitle). Inert text, never fetched at runtime.
  "https://radix-ui.com/",
  // Author contact links on the /about page. These are user-initiated navigation
  // anchors (target=_blank, rel=noopener) that open the operator's own browser on
  // click — the app NEVER auto-fetches them. Pinned to the exact author URLs so no
  // other github/linkedin origin can slip through.
  "https://linkedin.com/in/mohamed-hanii-0291031aa",
  "https://github.com/N1ghtFury74",
  // Author portfolio link on the /about page (same user-initiated-navigation
  // rationale as above). Pinned to the exact URL.
  "https://n1ghtfury74.github.io/",
];

const SCAN_EXT = new Set([".js", ".mjs", ".css", ".html", ".map", ".json", ".svg"]);
const URL_RE = /https?:\/\/[^\s"'`)<>\\]+/g;

const fail = (msg) => {
  console.error("OFFLINE CHECK FAIL:", msg);
  process.exit(1);
};

if (!existsSync(dist)) {
  fail("dist/ not found — run `npm run build` first.");
}

/** @param {string} dir */
function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      yield* walk(full);
    } else {
      yield full;
    }
  }
}

const isAllowed = (url) => ALLOW.some((prefix) => url.startsWith(prefix));

const violations = [];
let scanned = 0;

for (const file of walk(dist)) {
  if (!SCAN_EXT.has(extname(file))) continue;
  scanned += 1;
  const text = readFileSync(file, "utf-8");
  const matches = text.match(URL_RE);
  if (!matches) continue;
  for (const raw of matches) {
    // trim common trailing punctuation that the greedy class may capture
    const url = raw.replace(/[.,;:]+$/, "");
    if (!isAllowed(url)) {
      violations.push({ file: relative(dist, file), url });
    }
  }
}

if (violations.length > 0) {
  console.error(
    `OFFLINE CHECK FAIL: ${violations.length} external URL(s) found in dist/ ` +
      "(not same-origin API, not allowlisted):",
  );
  const seen = new Set();
  for (const v of violations) {
    const key = `${v.file} :: ${v.url}`;
    if (seen.has(key)) continue;
    seen.add(key);
    console.error(`  - ${v.file}: ${v.url}`);
  }
  process.exit(1);
}

console.log(
  `OFFLINE CHECK OK: scanned ${scanned} built file(s); no external runtime URLs. ` +
    "UI loads only vendored assets + the same-origin WRAITH API.",
);
