import { fileURLToPath, URL } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// WRAITH M7 web UI build config.
//
// `base: "/"` keeps asset refs absolute (`/assets/...`) so the SPA is served
// correctly from the FastAPI static mount at `/` with a history-API fallback:
// deep links like `/case/<id>/graph` still resolve `/assets/...` against the
// origin root. Offline by construction — Vite bundles every dep (framework,
// fonts, icons) into `dist/`; nothing is fetched from a CDN at runtime.
//
// The dev server proxies `/api` (incl. the `/api/v1/ws/progress` WebSocket) to
// the local uvicorn backend so dev + integrated modes use the same same-origin
// request paths (no CORS, no hard-coded host in the client).
const API_TARGET = process.env.WRAITH_API_TARGET ?? "http://127.0.0.1:8713";

export default defineConfig({
  base: "/",
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    port: 5173,
    host: "127.0.0.1",
    proxy: {
      "/api": {
        target: API_TARGET,
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    chunkSizeWarningLimit: 1500,
  },
});
