import { fileURLToPath, URL } from "node:url";

import { defineConfig } from "vitest/config";

// Unit tests for the Capability Graph pure logic (merge + interaction rules).
// Node environment — these are renderer-agnostic helpers, no DOM needed. The
// `@` alias mirrors the app build so test imports match source imports.
export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
