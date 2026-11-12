import { Clock, FileText, Network, ShieldAlert } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/states";
import { useLiveRun } from "@/store/run";

/**
 * FE-1 module placeholders. The Capability Graph canvas (sigma.js) is built in
 * FE-2 — this is the routed slot. Each renders a tasteful READY / NOT-READY
 * state driven by the case's run state, per the brief.
 */
function ModuleShell({
  icon: Icon,
  title,
  caseId,
  analyzed,
  readyBlurb,
  pendingBlurb,
}: {
  icon: typeof Network;
  title: string;
  caseId: string | undefined;
  analyzed: boolean;
  readyBlurb: React.ReactNode;
  pendingBlurb: React.ReactNode;
}) {
  return (
    <div className="p-6">
      <div className="mb-4 flex items-center gap-2">
        <Icon className="size-5 text-accent" />
        <h1 className="text-display">{title}</h1>
      </div>
      {analyzed ? (
        <EmptyState icon={Icon} title={`${title} — ready`} hint={readyBlurb} />
      ) : (
        <EmptyState
          icon={Clock}
          title="Ready once a case is analyzed"
          hint={pendingBlurb}
          action={
            caseId ? (
              <Button asChild size="sm" variant="secondary">
                <Link to={`/case/${encodeURIComponent(caseId)}/ingest`}>Go to Case &amp; Ingest</Link>
              </Button>
            ) : null
          }
        />
      )}
    </div>
  );
}

function useAnalyzed(): [string | undefined, boolean] {
  const { caseId } = useParams();
  const live = useLiveRun(caseId);
  return [caseId, live.state === "done"];
}

export function GraphPlaceholder() {
  const [caseId, analyzed] = useAnalyzed();
  return (
    <ModuleShell
      icon={Network}
      title="Capability Graph"
      caseId={caseId}
      analyzed={analyzed}
      readyBlurb="The capability graph maps the privilege terrain — who can reach Tier-0 and the paths between — the context for the hunt."
      pendingBlurb="Upload artifacts and run analysis to build the capability graph."
    />
  );
}

export function DossiersPlaceholder() {
  const [caseId, analyzed] = useAnalyzed();
  return (
    <ModuleShell
      icon={FileText}
      title="Dossiers"
      caseId={caseId}
      analyzed={analyzed}
      readyBlurb="Per-entity dossiers (identity, UAC flags, edges, ACEs, provenance) — the context behind every entity in the graph."
      pendingBlurb="Dossiers are generated from the analyzed directory graph."
    />
  );
}

export function RiskPlaceholder() {
  const [caseId, analyzed] = useAnalyzed();
  return (
    <ModuleShell
      icon={ShieldAlert}
      title="Risk"
      caseId={caseId}
      analyzed={analyzed}
      readyBlurb="Transparent per-node risk scoring and Tier-0 reachability — where to start the hunt."
      pendingBlurb="Risk scoring runs over the analyzed capability graph."
    />
  );
}

export function BaseliningPlaceholder() {
  const { caseId } = useParams();
  return (
    <div className="p-6">
      <EmptyState
        icon={Clock}
        title="Baselining — reserved"
        hint="Behavioral baselining of users, processes and hosts is a reserved module. The app shell holds its slot now so it lands as a route, not a re-architecture."
        action={
          caseId ? (
            <Button asChild size="sm" variant="secondary">
              <Link to={`/case/${encodeURIComponent(caseId)}/ingest`}>Back to Case &amp; Ingest</Link>
            </Button>
          ) : null
        }
      />
    </div>
  );
}
