import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo } from "react";
import { Link, useParams } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { api, ApiError, type ArtifactKindOut, type CatalogResponse, type CoverageReport } from "@/lib/api";
import { errorText } from "@/lib/reasons";
import { useCasesStore } from "@/store/cases";
import { AnalyzePanel } from "@/routes/ingest/AnalyzePanel";
import { CoveragePanel } from "@/routes/ingest/CoveragePanel";
import { CoverageVerdict } from "@/routes/ingest/CoverageVerdict";
import { FolderIngest } from "@/routes/ingest/FolderIngest";
import { UploadTile } from "@/routes/ingest/UploadTile";

/** Build per-kind unlock labels + "if absent" loss text from the coverage report. */
function useTileContext(coverage: CoverageReport | undefined) {
  return useMemo(() => {
    const labelById = new Map<string, string>();
    const lossByArtifact = new Map<string, string[]>();
    if (coverage) {
      for (const cap of coverage.capabilities) {
        labelById.set(cap.capability_id, cap.label);
        for (const r of cap.reasons) {
          const list = lossByArtifact.get(r.missing_artifact_id) ?? [];
          list.push(r.note);
          lossByArtifact.set(r.missing_artifact_id, list);
        }
      }
    }
    return { labelById, lossByArtifact };
  }, [coverage]);
}

export function IngestPage() {
  const { caseId } = useParams();
  const queryClient = useQueryClient();
  const addCase = useCasesStore((s) => s.addCase);

  // Track an attached-by-URL case locally so the selector/badges know it.
  useEffect(() => {
    if (caseId && !useCasesStore.getState().get(caseId)) {
      addCase({ caseId, operator: null, createdAt: null });
    }
  }, [caseId, addCase]);

  const catalogQuery = useQuery<CatalogResponse, ApiError>({
    queryKey: ["catalog", caseId],
    queryFn: () => api.catalog(caseId as string),
    enabled: Boolean(caseId),
  });
  const coverageQuery = useQuery<CoverageReport, ApiError>({
    queryKey: ["coverage", caseId],
    queryFn: () => api.coverage(caseId as string),
    enabled: Boolean(caseId),
  });

  const { labelById, lossByArtifact } = useTileContext(coverageQuery.data);

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: ["catalog", caseId] });
    void queryClient.invalidateQueries({ queryKey: ["coverage", caseId] });
  }

  if (!caseId) {
    return (
      <div className="p-6">
        <ErrorState
          title="No case selected"
          message="Select or create a case first."
          action={
            <Button asChild size="sm" variant="secondary">
              <Link to="/cases">Go to cases</Link>
            </Button>
          }
        />
      </div>
    );
  }

  const loadError = catalogQuery.error ?? coverageQuery.error;
  if (loadError) {
    const unknown = loadError.status === 404;
    return (
      <div className="p-6">
        <ErrorState
          title={unknown ? "Case not found" : "Failed to load case"}
          message={errorText(loadError)}
          action={
            <Button asChild size="sm" variant="secondary">
              <Link to="/cases">Back to cases</Link>
            </Button>
          }
        />
      </div>
    );
  }

  if (catalogQuery.isLoading || coverageQuery.isLoading || !catalogQuery.data || !coverageQuery.data) {
    return <LoadingState label="Loading case…" />;
  }

  const catalog = catalogQuery.data;
  const coverage = coverageQuery.data;
  const allTiles: ArtifactKindOut[] = [...catalog.required, ...catalog.optional];

  const renderTile = (kind: ArtifactKindOut) => (
    <UploadTile
      key={kind.id}
      caseId={caseId}
      kind={kind}
      unlockLabels={kind.unlocks.map((id) => labelById.get(id) ?? id)}
      lossWhenAbsent={lossByArtifact.get(kind.id) ?? []}
      onUploaded={invalidate}
    />
  );

  return (
    <div className="mx-auto max-w-[1400px] space-y-5 p-4 sm:p-5">
      <div>
        <h1 className="text-display">Case &amp; Ingest</h1>
        <p className="text-body text-muted-foreground">
          Case <span className="font-mono text-body-sm text-foreground">{caseId}</span> — add the dead-disk
          artifacts from this environment. Each one unlocks more of the terrain you can hunt:
          principals, their relationships, and the paths between. Coverage updates live; everything
          runs offline.
        </p>
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        {/* Left: folder auto-ingest + catalog tiles */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Auto-ingest a folder</CardTitle>
              <CardDescription>
                The fast path: point at a capture folder and WRAITH routes each file to the right
                artifact. The manual tiles below stay as the advanced fallback.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <FolderIngest caseId={caseId} onUploaded={invalidate} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Required</CardTitle>
              <CardDescription>
                The NTDS database is the minimum WRAITH needs to reconstruct the terrain — the
                directory, its principals, and how they relate.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3 sm:grid-cols-2">
              {catalog.required.map(renderTile)}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Optional</CardTitle>
              <CardDescription>
                Each optional artifact widens the terrain you can hunt — more context, more edges.
                Absent ones degrade coverage honestly — never silently.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3 sm:grid-cols-2">
              {catalog.optional.map(renderTile)}
            </CardContent>
          </Card>
        </div>

        {/* Right: coverage + analyze */}
        <div className="space-y-4">
          <AnalyzePanel caseId={caseId} coverage={coverage} />
          <Card>
            <CardHeader>
              <CardTitle>Coverage</CardTitle>
              <CardDescription>
                The hunting context this evidence set unlocks ({allTiles.filter((t) => t.uploaded).length}{" "}
                of {allTiles.length} artifact kinds present).
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <CoverageVerdict coverage={coverage} />
              <CoveragePanel coverage={coverage} />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
