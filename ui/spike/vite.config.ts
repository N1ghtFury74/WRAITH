import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Throwaway spike config. `base: "./"` keeps the built asset refs relative so the
// dist/ bundle is trivially self-contained / inspectable for the offline check.
export default defineConfig({
  plugins: [react()],
  base: "./",
  server: { port: 5173, host: "127.0.0.1" },
});
