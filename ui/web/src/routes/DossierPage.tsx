import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Clock, Loader2, Printer } from "lucide-react";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { DossierBody } from "@/components/dossier/DossierBody";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/ui/states";
import { useGlossary } from "@/hooks/useGlossary";
import { api, ApiError, type NodeDossier } from "@/lib/api";
import { errorText } from "@/lib/reasons";

export function DossierPage() {
  const { caseId, nodeId } = useParams();
  const [searchParams] = useSearchParams();
  // Per-source scope (M-MS2): a scoped dossier shows ONLY that source's view and
  // carries NO merge overlay (merge is the folded/unscoped case view, §5.4).
  const sourceId = searchParams.get("source_id") ?? undefined;
  const backTo = sourceId
    ? `/case/${encodeURIComponent(caseId as string)}/dossiers?source_id=${encodeURIComponent(sourceId)}`
    : `/case/${encodeURIComponent(caseId as string)}/dossiers`;

  const { data, isLoading, error } = useQuery<NodeDossier, ApiError>({
    queryKey: ["node", caseId, nodeId, sourceId],
    queryFn: () => api.node(caseId as string, nodeId as string, sourceId),
    enabled: Boolean(caseId && nodeId),
  });
  const glossary = useGlossary().data;

  if (!caseId || !nodeId) {
    return (
      <div className="p-6">
        <ErrorState title="No node selected" />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl space-y-5 px-4 py-5 sm:p-6">
      <div className="flex items-center gap-2">
        <Button asChild size="sm" variant="ghost">
          <Link to={backTo}>
            <ArrowLeft className="size-4" /> Dossiers
          </Link>
        </Button>
        <div className="ml-auto flex items-center gap-2">
          {/* Reserved Behavior tab (doc 18 §12) — keyed on node_id, not built. */}
          <Button size="sm" variant="ghost" disabled title="Behavioral baselining — a later milestone">
            <Clock className="size-4" /> Behavior
          </Button>
          <Button asChild size="sm" variant="secondary">
            <Link to={`/case/${encodeURIComponent(caseId)}/dossier/${encodeURIComponent(nodeId)}/print`}>
              <Printer className="size-4" /> Print / Save PDF
            </Link>
          </Button>
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center gap-2 py-16 text-body text-muted-foreground">
          <Loader2 className="size-4 animate-spin" /> Loading dossier…
        </div>
      ) : error ? (
        <ErrorState
          title={error.status === 404 ? "Node not found" : "Failed to load dossier"}
          message={errorText(error)}
        />
      ) : data ? (
        <DossierBody caseId={caseId} dossier={data} glossary={glossary} variant="screen" />
      ) : null}
    </div>
  );
}
