import { useQuery } from "@tanstack/react-query";
import {
  CheckCircle2,
  CircleDashed,
  Download,
  Landmark,
  List,
  Loader2,
  Network,
  Play,
  ScrollText,
  ShieldCheck,
  ShieldQuestion,
  TriangleAlert,
  XCircle,
} from "lucide-react";
import { Link } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { summarizeAdcsCoverage, escDcDecidable } from "@/lib/adcsCoverage";
import { summarizeCaHostCoverage } from "@/lib/caHostCoverage";
import { gpoHeadline, summarizeGpoCoverage } from "@/lib/gpoCoverage";
import { ADCS_EDGE_KINDS } from "@/lib/graph/encoding";
import { api, type CoverageReport, type PassState } from "@/lib/api";
import { reasonText } from "@/lib/reasons";
import { useAnalyzeRun } from "@/hooks/useAnalyzeRun";
import { cn } from "@/lib/utils";
import { useLiveRun } from "@/store/run";

/**
 * AD CS coverage honesty (doc 16 §C): turns the run's `skip_counts` into rows the
 * operator can read without mistaking a NULL ESC verdict for "clean". Keeps the
 * two undecidability planes distinct (no SYSTEM hive vs hive-present-value-unset)
 * and flags the CA-host ESCs (6/7/11/16) as undecidable, not safe. Only renders
 * when there is something AD CS to say.
 */
function AdcsCoverageCard({
  skipCounts,
  systemHivePresent,
  adcsEdgesPresent,
}: {
  skipCounts: Record<string, number>;
  systemHivePresent: boolean;
  /** True when the analyzed graph actually carries AD CS edges — gates the calm
   * "decidable" affirmative so this card is never noise on a no-AD CS domain. */
  adcsEdgesPresent: boolean;
}) {
  const rows = summarizeAdcsCoverage(skipCounts);
  const decidable = adcsEdgesPresent && escDcDecidable(skipCounts, systemHivePresent);
  if (rows.length === 0 && !decidable) return null;
  return (
    <div className="space-y-2 rounded border border-border bg-surface-raised/50 p-3">
      <div className="flex items-center gap-1.5">
        <ShieldQuestion className="size-3.5 text-degraded" />
        <p className="text-caption font-medium text-foreground">AD CS coverage</p>
        <Badge variant="degraded" title="Certificate-services analysis is synthetic-only in v1.">
          synthetic
        </Badge>
      </div>
      {decidable ? (
        <p className="flex items-start gap-1.5 text-micro leading-snug text-available">
          <CheckCircle2 className="mt-0.5 size-3 shrink-0" />
          <span>
            DC cert-mapping config read from the SYSTEM hive — ESC9/ESC10 decidable on the imaged DC.
          </span>
        </p>
      ) : null}
      {rows.length > 0 ? (
        <ul className="space-y-1.5">
          {rows.map((r) => (
            <li key={r.id} className="flex items-start gap-1.5 text-micro leading-snug">
              <TriangleAlert
                className={cn(
                  "mt-0.5 size-3 shrink-0",
                  r.status === "undecidable" ? "text-degraded" : "text-muted-foreground",
                )}
              />
              <span className="min-w-0 flex-1">
                <span className="font-medium text-foreground">{r.label}</span>
                <span className="ml-1 font-mono tabular-nums text-muted-foreground">
                  ({r.count})
                </span>
                <span className="mt-0.5 block text-muted-foreground">{r.note}</span>
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

/**
 * Group Policy coverage honesty (Research 22 §B) — the INVERSE polarity of the AD
 * CS card. GPO inferred edges are a SUPERSET: WRAITH emits the union of every
 * non-disabled GPO link and, dead-disk, cannot replay live RSoP (security
 * filtering, WMI filters, block-inheritance, link precedence, enforcement). So
 * the message is "candidate paths to VERIFY — this set over-states, never
 * under-states; there are NO missed GPO paths here." The not-run state reads "not
 * analyzed", never "none exist". Numbers come only from the run's
 * `coverage_counts` / `skip_counts` — nothing is invented client-side.
 */
function GpoCoverageCard({
  coverageCounts,
  skipCounts,
  sysvolPresent,
}: {
  coverageCounts: Record<string, number>;
  skipCounts: Record<string, number>;
  sysvolPresent: boolean;
}) {
  const rows = summarizeGpoCoverage(skipCounts);
  const head = gpoHeadline(coverageCounts);
  const showSecondary = head.inferredEdges > 0 || head.adminToEdges > 0;
  return (
    <div className="space-y-2 rounded border border-border bg-surface-raised/50 p-3">
      <div className="flex items-center gap-1.5">
        <ScrollText className="size-3.5 text-degraded" />
        <p className="text-caption font-medium text-foreground">Group Policy coverage</p>
        <Badge
          variant="degraded"
          title="Every Group Policy edge is inferred from SYSVOL, not resolved against live RSoP."
        >
          inferred
        </Badge>
      </div>
      {!sysvolPresent ? (
        <p className="flex items-start gap-1.5 text-micro leading-snug text-muted-foreground">
          <ShieldQuestion className="mt-0.5 size-3 shrink-0 text-degraded" />
          <span>
            <span className="font-medium text-foreground">No SYSVOL uploaded</span> — Group Policy
            edges were not computed. Their absence from the graph means &ldquo;not analyzed,&rdquo;
            not &ldquo;none exist.&rdquo; Upload SYSVOL to map GPO-pushed local-admin / rights paths.
          </span>
        </p>
      ) : (
        <>
          {/* Persistent caveat — always shown when GPO analysis ran. This set
              over-states (candidate paths to verify) and never under-states. */}
          <p className="text-micro leading-snug text-muted-foreground">
            Group Policy edges are inferred from SYSVOL: the union of every non-disabled GPO link.
            Dead-disk, WRAITH cannot replay RSoP — security filtering, WMI filters,
            block-inheritance, link precedence and enforcement are not evaluated. Treat each GPO edge
            as a candidate path to verify, never a confirmed grant. This set over-states (it may
            include paths the live filters would prune) and never under-states — there are no missed
            GPO paths here.
          </p>
          {/* Live-counts strip — pre-dedup, per-instance emission figures. */}
          <p className="text-micro leading-snug">
            <span className="font-mono tabular-nums text-foreground">{head.gposProcessed}</span>{" "}
            <span className="text-muted-foreground">GPOs processed</span>
            <span className="text-muted-foreground"> · </span>
            <span className="font-mono tabular-nums text-foreground">{head.inferredEdges}</span>{" "}
            <span className="text-muted-foreground">inferred edges emitted</span>
          </p>
          {showSecondary ? (
            <p className="text-micro leading-snug text-muted-foreground">
              AdminTo <span className="font-mono tabular-nums">{head.adminToEdges}</span> ·
              local-group total <span className="font-mono tabular-nums">{head.localGroupEdges}</span>{" "}
              · privilege <span className="font-mono tabular-nums">{head.privilegeEdges}</span>.
            </p>
          ) : null}
          {rows.length > 0 ? (
            <ul className="space-y-1.5">
              {rows.map((r) => (
                <li key={r.id} className="flex items-start gap-1.5 text-micro leading-snug">
                  <TriangleAlert
                    className={cn(
                      "mt-0.5 size-3 shrink-0",
                      r.tone === "degraded" ? "text-degraded" : "text-muted-foreground",
                    )}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="font-medium text-foreground">{r.label}</span>
                    <span className="ml-1 font-mono tabular-nums text-muted-foreground">
                      ({r.count})
                    </span>
                    <span className="mt-0.5 block text-muted-foreground">{r.note}</span>
                  </span>
                </li>
              ))}
            </ul>
          ) : null}
        </>
      )}
    </div>
  );
}

/**
 * Enterprise-CA-host coverage honesty (module 35b) — the HONEST AD CS polarity:
 * more evidence means more findings, never fewer (the inverse of the GPO card's
 * over-stating superset). ManageCA / ManageCertificates and ESC6/7/11/16 live only
 * in the CA host's own registry, so WITHOUT the CA host hive they are undecidable —
 * counted gaps, not false-negatives — and WITH it they become decidable. The
 * SYSTEM-vs-SOFTWARE split is stated honestly: SYSTEM unlocks the CA roles + ESC,
 * the optional SOFTWARE hive adds only the DCOM activation posture. Numbers come
 * only from the run's counts; the card hides when there is nothing CA-host to say.
 */
function CaHostCoverageCard({
  coverageCounts,
  skipCounts,
  caHostHivePresent,
}: {
  coverageCounts: Record<string, number>;
  skipCounts: Record<string, number>;
  caHostHivePresent: boolean;
}) {
  const cov = summarizeCaHostCoverage(coverageCounts, skipCounts, caHostHivePresent);
  if (!cov.relevant) return null;
  const decidable = cov.state === "decidable";
  return (
    <div className="space-y-2 rounded border border-border bg-surface-raised/50 p-3">
      <div className="flex items-center gap-1.5">
        <Landmark className="size-3.5 text-degraded" />
        <p className="text-caption font-medium text-foreground">Certificate-authority host coverage</p>
        <Badge
          variant={decidable ? "available" : "degraded"}
          title="CA-host ESCs are decidable only from the CA host's own registry — never from ntds.dit alone."
        >
          {decidable ? "decided" : "undecidable"}
        </Badge>
      </div>

      {/* Persistent polarity caveat — the inverse of the GPO superset. More evidence
          = more findings; a blank here is "not yet decided", never "clean". */}
      <p className="text-micro leading-snug text-muted-foreground">
        For the CA host, more evidence means more findings — the inverse of Group Policy. ManageCA /
        ManageCertificates and ESC6 / ESC7 / ESC11 / ESC16 live only in the CA host registry, so
        without it they are undecidable (counted gaps, not false-negatives — a blank is &ldquo;not yet
        decided,&rdquo; never &ldquo;clean&rdquo;). The CA host <span className="text-foreground">SYSTEM</span>{" "}
        hive makes the CA roles + ESC decidable; the optional{" "}
        <span className="text-foreground">SOFTWARE</span> hive adds the machine-wide DCOM posture.
      </p>

      {decidable ? (
        <>
          <p className="flex items-start gap-1.5 text-micro leading-snug text-available">
            <ShieldCheck className="mt-0.5 size-3 shrink-0" />
            <span>
              CA host registry read — ManageCA / ManageCertificates and ESC6 / ESC11 / ESC16 are
              decidable on this CA.
            </span>
          </p>
          <p className="text-micro leading-snug">
            <span className="font-mono tabular-nums text-foreground">{cov.manageCa}</span>{" "}
            <span className="text-muted-foreground">ManageCA</span>
            <span className="text-muted-foreground"> · </span>
            <span className="font-mono tabular-nums text-foreground">{cov.manageCertificates}</span>{" "}
            <span className="text-muted-foreground">ManageCertificates</span>
            <span className="text-muted-foreground"> · </span>
            <span className="font-mono tabular-nums text-foreground">{cov.esc6a}</span>{" "}
            <span className="text-muted-foreground">ESC6a</span>
            <span className="text-muted-foreground"> · </span>
            <span className="font-mono tabular-nums text-foreground">{cov.nodeFindings}</span>{" "}
            <span className="text-muted-foreground">host findings</span>
          </p>
          <p className="flex items-start gap-1.5 text-micro leading-snug text-muted-foreground">
            {cov.dcomAbsent > 0 ? (
              <>
                <ShieldQuestion className="mt-0.5 size-3 shrink-0 text-degraded" />
                <span>
                  <span className="font-medium text-foreground">SOFTWARE hive absent</span> — the
                  machine-wide DCOM posture is undecidable (counted:{" "}
                  <span className="font-mono tabular-nums">{cov.dcomAbsent}</span>). SYSTEM unlocked the
                  CA roles + ESC; add the SOFTWARE hive for the DCOM activation summary (ESC7 context).
                </span>
              </>
            ) : (
              <>
                <ShieldCheck className="mt-0.5 size-3 shrink-0 text-available" />
                <span>DCOM activation posture decided from the CA host SOFTWARE hive.</span>
              </>
            )}
          </p>
        </>
      ) : (
        <p className="flex items-start gap-1.5 text-micro leading-snug text-muted-foreground">
          <ShieldQuestion className="mt-0.5 size-3 shrink-0 text-degraded" />
          <span>
            <span className="font-medium text-foreground">No CA host registry read</span> — ManageCA /
            ManageCertificates and ESC6 / ESC7 / ESC11 / ESC16 stay undecidable
            {cov.factsAbsent > 0 ? (
              <>
                {" "}(counted: <span className="font-mono tabular-nums">{cov.factsAbsent}</span>)
              </>
            ) : null}
            . Upload the CA host SYSTEM hive to decide them; add the SOFTWARE hive for DCOM posture.
          </span>
        </p>
      )}

      {cov.gaps.length > 0 ? (
        <ul className="space-y-1.5">
          {cov.gaps.map((r) => (
            <li key={r.id} className="flex items-start gap-1.5 text-micro leading-snug">
              <TriangleAlert
                className={cn(
                  "mt-0.5 size-3 shrink-0",
                  r.tone === "undecidable" ? "text-degraded" : "text-muted-foreground",
                )}
              />
              <span className="min-w-0 flex-1">
                <span className="font-medium text-foreground">{r.label}</span>
                <span className="ml-1 font-mono tabular-nums text-muted-foreground">({r.count})</span>
                <span className="mt-0.5 block text-muted-foreground">{r.note}</span>
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

const PASS_ICON: Record<PassState, typeof CheckCircle2> = {
  done: CheckCircle2,
  running: Loader2,
  pending: CircleDashed,
};

function ModeCard({
  icon: Icon,
  title,
  ready,
  to,
  blurb,
}: {
  icon: typeof Network;
  title: string;
  ready: boolean;
  to: string;
  blurb: string;
}) {
  return (
    <div
      className={cn(
        "rounded-lg border p-3",
        ready ? "border-available/40 bg-available/5" : "border-border bg-surface",
      )}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className={cn("size-4", ready ? "text-available" : "text-muted-foreground")} />
          <span className="text-body font-medium">{title}</span>
        </div>
        <Badge variant={ready ? "available" : "outline"}>{ready ? "READY" : "not ready"}</Badge>
      </div>
      <p className="mt-1 text-caption text-muted-foreground">{blurb}</p>
      {ready ? (
        <Button asChild size="sm" variant="secondary" className="mt-2">
          <Link to={to}>Open {title}</Link>
        </Button>
      ) : null}
    </div>
  );
}

/** Analyze trigger + live loading bar + pass checklist + Listing/Graph readiness. */
export function AnalyzePanel({ caseId, coverage }: { caseId: string; coverage: CoverageReport }) {
  const { start, starting, startError } = useAnalyzeRun(caseId);
  const live = useLiveRun(caseId);

  const running = live.state === "running" || live.state === "pending";
  const done = live.state === "done";
  const failed = live.state === "failed";

  // Poll detailed run status (per-pass states + result counts) while a run exists.
  const { data: status } = useQuery({
    queryKey: ["run", caseId, live.runId],
    queryFn: () => api.runStatus(caseId, live.runId as string),
    enabled: Boolean(live.runId),
    refetchInterval: (q) => {
      const s = q.state.data?.state;
      return s === "done" || s === "failed" ? false : 600;
    },
  });

  const passes = status?.passes ?? [];

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle>Analyze</CardTitle>
        <div className="flex items-center gap-2">
          {!coverage.can_analyze ? (
            <span className="flex items-center gap-1 text-caption text-degraded">
              <TriangleAlert className="size-3.5" /> ntds.dit required
            </span>
          ) : null}
          <Button
            size="sm"
            onClick={() => void start({})}
            disabled={!coverage.can_analyze || running || starting}
          >
            {running ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4" />}
            {running ? "Analyzing…" : done ? "Re-analyze" : "Run analysis"}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {startError ? (
          <p className="rounded border border-unavailable/30 bg-unavailable/5 px-2 py-1 text-caption text-unavailable">
            {reasonText(startError.reason)}
          </p>
        ) : null}

        {/* Loading % bar */}
        {(running || done) && !failed ? (
          <div className="space-y-1">
            <div className="flex items-center justify-between text-caption">
              <span className="text-muted-foreground">
                {done ? "complete" : live.currentPass ? `running: ${live.currentPass}` : "starting…"}
              </span>
              <span className="font-mono">{live.percent}%</span>
            </div>
            <Progress value={live.percent} tone={done ? "available" : "accent"} />
          </div>
        ) : null}

        {failed ? (
          <div className="flex items-start gap-2 rounded border border-unavailable/30 bg-unavailable/5 px-3 py-2 text-caption text-unavailable">
            <XCircle className="mt-0.5 size-4 shrink-0" />
            <div>
              <p className="font-medium">Analysis failed</p>
              <p className="font-mono text-micro">{live.error ?? "unknown error"}</p>
            </div>
          </div>
        ) : null}

        {/* Pass checklist */}
        {passes.length > 0 ? (
          <ul className="space-y-1">
            {passes.map((p) => {
              const Icon = PASS_ICON[p.state];
              return (
                <li key={p.id} className="flex items-center gap-2 text-caption">
                  <Icon
                    className={cn(
                      "size-3.5",
                      p.state === "done"
                        ? "text-available"
                        : p.state === "running"
                          ? "animate-spin text-accent"
                          : "text-muted-foreground",
                    )}
                  />
                  <span className={p.state === "pending" ? "text-muted-foreground" : "text-foreground"}>
                    {p.label}
                  </span>
                </li>
              );
            })}
          </ul>
        ) : null}

        {/* Result summary on done */}
        {done && status?.result ? (
          <div className="grid grid-cols-2 gap-2 rounded border border-border bg-surface-raised/50 p-3 text-caption">
            <div>
              <p className="text-muted-foreground">Nodes</p>
              <p className="font-mono text-body-sm tabular-nums text-foreground">{status.result.node_count}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Edges</p>
              <p className="font-mono text-body-sm tabular-nums text-foreground">{status.result.edge_count}</p>
            </div>
            <div className="col-span-2 space-y-1.5">
              <p className="text-muted-foreground">Export</p>
              {status.export_download_url ? (
                <>
                  <Button asChild size="sm" className="w-full sm:w-auto">
                    <a
                      download
                      href={status.export_download_url}
                      aria-label="Download BloodHound CE export zip"
                    >
                      <Download className="size-4" />
                      Download BloodHound .zip
                    </a>
                  </Button>
                  <p className="truncate font-mono text-micro text-muted-foreground">
                    {status.result.export_zip_rel.split("/").pop()}
                  </p>
                  <p className="text-micro text-muted-foreground">
                    Import into BloodHound CE.
                  </p>
                </>
              ) : (
                <p className="text-micro text-muted-foreground">
                  BloodHound export not available for this run.
                </p>
              )}
            </div>
          </div>
        ) : null}

        {/* AD CS coverage honesty — keeps the undecidable planes distinct so a
            null ESC verdict never reads as "clean" (doc 16 §C). */}
        {done && status ? (
          <AdcsCoverageCard
            skipCounts={status.skip_counts}
            systemHivePresent={coverage.present_kinds.includes("system_hive")}
            adcsEdgesPresent={Object.entries(status.result?.edge_kind_counts ?? {}).some(
              ([kind, count]) => count > 0 && ADCS_EDGE_KINDS.has(kind),
            )}
          />
        ) : null}

        {/* Group Policy coverage honesty — the inverse polarity of AD CS: GPO
            inferred edges are a SUPERSET WRAITH cannot RSoP-resolve offline, so the
            card frames them as candidate paths to verify and the not-run state as
            "not analyzed", never "none exist" (Research 22 §B). */}
        {done && status ? (
          <GpoCoverageCard
            coverageCounts={status.coverage_counts}
            skipCounts={status.skip_counts}
            sysvolPresent={coverage.present_kinds.includes("sysvol")}
          />
        ) : null}

        {/* Enterprise-CA-host coverage honesty — the HONEST AD CS polarity: the CA
            host registry is the ONLY place ManageCA/ESC6/7/11/16 are decidable, so
            without it they are counted gaps (never false-negatives), and the
            SYSTEM-vs-SOFTWARE split (CA roles+ESC vs DCOM) is stated honestly
            (module 35b). */}
        {done && status ? (
          <CaHostCoverageCard
            coverageCounts={status.coverage_counts}
            skipCounts={status.skip_counts}
            caHostHivePresent={coverage.present_kinds.includes("ca_host_registry")}
          />
        ) : null}

        {/* Mode readiness */}
        <div className="grid gap-2 sm:grid-cols-2">
          <ModeCard
            icon={List}
            title="Listing"
            ready={done}
            to={`/case/${encodeURIComponent(caseId)}/dossiers`}
            blurb="Browse every entity and its dossier — the per-entity context for the hunt."
          />
          <ModeCard
            icon={Network}
            title="Graph"
            ready={done}
            to={`/case/${encodeURIComponent(caseId)}/graph`}
            blurb="The capability graph — who can reach Tier-0, and the paths between."
          />
        </div>
      </CardContent>
    </Card>
  );
}
