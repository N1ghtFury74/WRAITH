import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { ArrowLeft, Loader2, Printer } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { DossierBody } from "@/components/dossier/DossierBody";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/ui/states";
import { useGlossary } from "@/hooks/useGlossary";
import { api, ApiError, type NodeDossier } from "@/lib/api";
import { errorText } from "@/lib/reasons";

/** Standalone single-dossier print view (doc 18 §4): print stylesheet + window.print(). */
export function DossierPrintPage() {
  const { caseId, nodeId } = useParams();
  const printed = useRef(false);

  const { data, isLoading, error } = useQuery<NodeDossier, ApiError>({
    queryKey: ["node", caseId, nodeId],
    queryFn: () => api.node(caseId as string, nodeId as string),
    enabled: Boolean(caseId && nodeId),
  });
  const glossary = useGlossary().data;

  useEffect(() => {
    if (data && !printed.current) {
      printed.current = true;
      // Defer so the DOM (incl. lazy sections already fetched) has painted.
      const t = window.setTimeout(() => window.print(), 400);
      return () => window.clearTimeout(t);
    }
  }, [data]);

  if (!caseId || !nodeId) return <ErrorState title="No node selected" />;

  return (
    <div className="print-root min-h-full bg-background p-6">
      <div className="no-print mb-4 flex items-center gap-2">
        <Button asChild size="sm" variant="ghost">
          <Link to={`/case/${encodeURIComponent(caseId)}/dossier/${encodeURIComponent(nodeId)}`}>
            <ArrowLeft className="size-4" /> Back
          </Link>
        </Button>
        <Button size="sm" className="ml-auto" onClick={() => window.print()}>
          <Printer className="size-4" /> Print / Save PDF
        </Button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center gap-2 py-16 text-body text-muted-foreground">
          <Loader2 className="size-4 animate-spin" /> Loading dossier…
        </div>
      ) : error ? (
        <ErrorState title="Failed to load dossier" message={errorText(error)} />
      ) : data ? (
        <div className="mx-auto max-w-4xl">
          <DossierBody caseId={caseId} dossier={data} glossary={glossary} variant="print" />
        </div>
      ) : null}
    </div>
  );
}
