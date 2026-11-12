import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router-dom";

import { DensityProvider } from "@/components/providers/DensityProvider";
import { ThemeProvider } from "@/components/providers/ThemeProvider";
import { router } from "@/router";

import "@/index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Offline, local backend: refetch is cheap, but avoid surprise refetches
      // mid-interaction. Ingest views invalidate explicitly after mutations.
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 2_000,
    },
  },
});

const rootEl = document.getElementById("root");
if (!rootEl) {
  throw new Error("WRAITH UI: #root mount node missing from index.html");
}

createRoot(rootEl).render(
  <StrictMode>
    <ThemeProvider>
      <DensityProvider>
        <QueryClientProvider client={queryClient}>
          <RouterProvider router={router} future={{ v7_startTransition: true }} />
        </QueryClientProvider>
      </DensityProvider>
    </ThemeProvider>
  </StrictMode>,
);
