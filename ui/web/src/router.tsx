import { createBrowserRouter, Navigate } from "react-router-dom";

import { AppShell } from "@/components/shell/AppShell";
import { AboutPage } from "@/routes/AboutPage";
import { CasesPage } from "@/routes/CasesPage";
import { DossierBatchPrintPage } from "@/routes/DossierBatchPrintPage";
import { DossierPage } from "@/routes/DossierPage";
import { DossierPrintPage } from "@/routes/DossierPrintPage";
import { DossiersPage } from "@/routes/DossiersPage";
import { GraphPage } from "@/routes/GraphPage";
import { IngestPage } from "@/routes/IngestPage";
import { LimitationsPage } from "@/routes/LimitationsPage";
import { NotFoundPage } from "@/routes/NotFoundPage";
import { RiskPage } from "@/routes/RiskPage";
import { SourcesPage } from "@/routes/SourcesPage";
import { BaseliningPlaceholder } from "@/routes/placeholders";

/**
 * Browser router. A `createBrowserRouter` (history API) pairs with the FastAPI
 * SPA fallback: any unmatched path serves `index.html`, and the client resolves
 * the route. The selected `case_id` lives in the URL (`/case/:caseId/...`), the
 * single source of truth for which case every view reads.
 */
export const router = createBrowserRouter(
  [
    // Standalone print routes (no app shell) — static "print" segment outranks
    // the dynamic :nodeId so /dossier/print (batch) and /dossier/:id/print resolve.
    { path: "case/:caseId/dossier/print", element: <DossierBatchPrintPage /> },
    { path: "case/:caseId/dossier/:nodeId/print", element: <DossierPrintPage /> },
    {
      element: <AppShell />,
      children: [
        { index: true, element: <Navigate to="/cases" replace /> },
        { path: "about", element: <AboutPage /> },
        { path: "limitations", element: <LimitationsPage /> },
        { path: "cases", element: <CasesPage /> },
        { path: "case/:caseId", element: <Navigate to="ingest" replace /> },
        { path: "case/:caseId/ingest", element: <IngestPage /> },
        { path: "case/:caseId/sources", element: <SourcesPage /> },
        { path: "case/:caseId/graph", element: <GraphPage /> },
        { path: "case/:caseId/dossiers", element: <DossiersPage /> },
        { path: "case/:caseId/dossier/:nodeId", element: <DossierPage /> },
        { path: "case/:caseId/risk", element: <RiskPage /> },
        { path: "case/:caseId/baselining", element: <BaseliningPlaceholder /> },
        { path: "*", element: <NotFoundPage /> },
      ],
    },
  ],
  {
    // Opt in to v7 behaviour now (silences v6 deprecation console warnings;
    // keeps the console clean for the showcase and eases the eventual v7 bump).
    future: {
      v7_relativeSplatPath: true,
      v7_fetcherPersist: true,
      v7_normalizeFormMethod: true,
      v7_partialHydration: true,
      v7_skipActionErrorRevalidation: true,
    },
  },
);
