import { useQueries, useQuery } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { ArrowLeft, Loader2, Printer } from "lucide-react";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { DossierBody } from "@/components/dossier/DossierBody";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/ui/states";
import { useGlossary } from "@/hooks/useGlossary";
import { api, type NodeDossier } from "@/lib/api";

const BATCH_CAP = 200;

/** Resolve the id set + a total count from the ?ids / ?preset / ?kind params. */
function useBatchIds(caseId: string): { ids: string[]; total: number; title: string; loading: boolean } {
  const [sp] = useSearchParams();
  const idsParam = sp.get("ids");
  const preset = sp.get("preset");
  const kind = sp.get("kind");

  const explicit = idsParam ? idsParam.split(",").filter(Boolean) : null;

  const tier0 = useQuery({
    queryKey: ["batch-tier0", caseId],
    queryFn: () => api.riskNodes(caseId, { limit: BATCH_CAP, min_score: 0 }),
    enabled: !explicit && preset === "tier0",
  });
  const byKind = useQuery({
    queryKey: ["batch-kind", caseId, kind],
    queryFn: () => api.nodesPage(caseId, { kind: kind as string, limit: BATCH_CAP }),
    enabled: !explicit && preset !== "tier0" && Boolean(kind),
  });

  if (explicit) {
    return { ids: explicit.slice(0, BATCH_CAP), total: explicit.length, title: "Selected dossiers", loading: false };
  }
  if (preset === "tier0") {
    const t0 = (tier0.data ?? []).filter((n) => n.tier === 0);
    return { ids: t0.map((n) => n.node_id).slice(0, BATCH_CAP), total: t0.length, title: "All Tier-0 dossiers", loading: tier0.isLoading };
  }
  if (kind) {
    const entries = byKind.data?.entries ?? [];
    return {
      ids: entries.map((e) => e.node_id).slice(0, BATCH_CAP),
      total: byKind.data?.total_matched ?? entries.length,
      title: `All ${kind} dossiers`,
      loading: byKind.isLoading,
    };
  }
  return { ids: [], total: 0, title: "Batch dossiers", loading: false };
}

function BatchDossiers({ caseId, ids }: { caseId: string; ids: string[] }) {
  const printed = useRef(false);
  const glossary = useGlossary().data;
  const results = useQueries({
    queries: ids.map((id) => ({
      queryKey: ["node", caseId, id],
      queryFn: () => api.node(caseId, id),
    })),
  });

  const allSettled = results.length > 0 && results.every((r) => r.isSuccess || r.isError);

  useEffect(() => {
    if (allSettled && !printed.current) {
      printed.current = true;
      const t = window.setTimeout(() => window.print(), 500);
      return () => window.clearTimeout(t);
    }
  }, [allSettled]);

  if (!allSettled) {
    const done = results.filter((r) => r.isSuccess || r.isError).length;
    return (
      <div className="flex items-center justify-center gap-2 py-16 text-body text-muted-foreground">
        <Loader2 className="size-4 animate-spin" /> Loading dossiers {done}/{ids.length}…
      </div>
    );
  }

  const dossiers = results.map((r) => r.data).filter((d): d is NodeDossier => Boolean(d));
  return (
    <div className="mx-auto max-w-4xl space-y-8">
      {dossiers.map((d) => (
        // Batch omits the per-node pathfinding sections (bounded: no N×2 path
        // queries across up to 200 entities); each node's own print includes them.
        <DossierBody key={d.node_id} caseId={caseId} dossier={d} glossary={glossary} includePaths={false} variant="print" />
      ))}
    </div>
  );
}

/** Standalone batch print view (doc 18 §4): stacked dossiers, one per page. */
export function DossierBatchPrintPage() {
  const { caseId } = useParams();
  const { ids, total, title, loading } = useBatchIds(caseId ?? "");

  if (!caseId) return <ErrorState title="No case selected" />;

  return (
    <div className="print-root min-h-full bg-background p-6">
      <div className="no-print mb-4 flex items-center gap-3">
        <Button asChild size="sm" variant="ghost">
          <Link to={`/case/${encodeURIComponent(caseId)}/dossiers`}>
            <ArrowLeft className="size-4" /> Dossiers
          </Link>
        </Button>
        <span className="text-body text-muted-foreground">
          {title} — printing <span className="font-mono tabular-nums text-foreground">{ids.length}</span>
          {total > ids.length ? <> of <span className="font-mono tabular-nums">{total}</span> (capped at {BATCH_CAP})</> : null}
        </span>
        <Button size="sm" className="ml-auto" disabled={ids.length === 0} onClick={() => window.print()}>
          <Printer className="size-4" /> Print / Save PDF
        </Button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center gap-2 py-16 text-body text-muted-foreground">
          <Loader2 className="size-4 animate-spin" /> Resolving set…
        </div>
      ) : ids.length === 0 ? (
        <ErrorState title="Nothing to print" message="No dossiers matched this selection." />
      ) : (
        <BatchDossiers caseId={caseId} ids={ids} />
      )}
    </div>
  );
}
