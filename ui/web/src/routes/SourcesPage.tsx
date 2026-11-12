import { useQueries, useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  CircleSlash,
  Database,
  FileText,
  GitMerge,
  Globe,
  Layers,
  Loader2,
  Network,
  Server,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/states";
import {
  api,
  ApiError,
  type CaseSummary,
  type DivergenceLedger,
  type MergeReport,
  type SourceCoverage,
  type SourceInfo,
  type SourceList,
} from "@/lib/api";
import {
  aggregateCounts,
  crossDomainSignals,
  distinctDomains,
  distinctForests,
  hasLabelMismatch,
} from "@/lib/multiSource";
import { errorText } from "@/lib/reasons";
import { cn, shortSha } from "@/lib/utils";

export function SourcesPage() {
  const { caseId } = useParams();

  const summaryQuery = useQuery<CaseSummary, ApiError>({
    queryKey: ["summary", caseId],
    queryFn: () => api.summary(caseId as string),
    enabled: Boolean(caseId),
    retry: false,
  });

  const sourcesQuery = useQuery<SourceList, ApiError>({
    queryKey: ["sources", caseId],
    queryFn: () => api.sources(caseId as string),
    enabled: Boolean(caseId) && summaryQuery.isSuccess,
  });

  const sources = sourcesQuery.data?.sources ?? [];

  // Fetch each source's coverage once — it powers both the per-source cards AND
  // the aggregated cross-domain honesty card (one source of truth, no re-fetch).
  const coverageQueries = useQueries({
    queries: sources.map((s) => ({
      queryKey: ["source-coverage", caseId, s.source_id],
      queryFn: () => api.sourceCoverage(caseId as string, s.source_id),
      enabled: Boolean(caseId),
    })),
  });

  if (!caseId) {
    return (
      <div className="p-6">
        <ErrorState title="No case selected" />
      </div>
    );
  }

  if (summaryQuery.error) {
    const notReady = summaryQuery.error.status === 409 || summaryQuery.error.status === 400;
    return (
      <div className="p-6">
        <ErrorState
          title={notReady ? "Case not analyzed yet" : "Failed to load"}
          message={notReady ? "Run analysis first to inspect its sources." : errorText(summaryQuery.error)}
          action={
            <Button asChild size="sm" variant="secondary">
              <Link to={`/case/${encodeURIComponent(caseId)}/ingest`}>Go to Case &amp; Ingest</Link>
            </Button>
          }
        />
      </div>
    );
  }

  const coverages = coverageQueries
    .map((q) => q.data)
    .filter((d): d is SourceCoverage => Boolean(d));
  const agg = aggregateCounts(coverages);
  const signals = crossDomainSignals(agg);
  const domains = distinctDomains(sources);
  const forests = distinctForests(sources);
  const gcSources = sources.filter((s) => s.is_global_catalog).length;

  return (
    <div className="mx-auto max-w-6xl space-y-5 p-4 sm:p-5">
      <div className="flex flex-wrap items-center gap-2">
        <Layers className="size-5 text-accent" />
        <h1 className="text-display tracking-tight">Sources</h1>
        <span className="text-body text-muted-foreground">
          every DC artifact set in this case — viewed standalone by default
        </span>
      </div>

      {/* Case shape summary strip */}
      <div className="flex flex-wrap gap-2">
        <ShapeStat icon={Database} value={sources.length} label={`source${sources.length === 1 ? "" : "s"}`} />
        <ShapeStat icon={Globe} value={domains.length} label={`domain${domains.length === 1 ? "" : "s"}`} />
        <ShapeStat
          icon={Network}
          value={forests.length}
          label={forests.length > 1 ? "forests (cross-forest)" : "forest"}
          tone={forests.length > 1 ? "accent" : undefined}
        />
        {gcSources > 0 ? (
          <ShapeStat icon={Server} value={gcSources} label="global catalog" tone="degraded" />
        ) : null}
      </div>

      {sourcesQuery.isLoading ? (
        <SkeletonRows rows={3} />
      ) : sources.length === 0 ? (
        <EmptyState
          title="No sources recorded"
          hint="This case was ingested before multi-source tagging, or has a single untagged source. Re-ingest with a DC label to list it here."
        />
      ) : (
        <>
          {/* Per-source coverage cards (the default per-source-separate landing). */}
          <section className="space-y-2">
            <h2 className="eyebrow">Per-source coverage</h2>
            <div className="grid gap-3 lg:grid-cols-2">
              {sources.map((s, i) => (
                <SourceCard
                  key={s.source_id}
                  caseId={caseId}
                  source={s}
                  coverage={coverageQueries[i]?.data}
                  loading={coverageQueries[i]?.isLoading ?? false}
                />
              ))}
            </div>
          </section>

          {/* Cross-domain honesty card (Phase 1). */}
          <CrossDomainCard signals={signals} domains={domains} forests={forests} gcSources={gcSources} />

          {/* Opt-in merge + divergence (now functional). */}
          <MergePanel caseId={caseId} sources={sources} />
        </>
      )}
    </div>
  );
}

/** A compact icon + count + label chip for the case-shape summary strip. */
function ShapeStat({
  icon: Icon,
  value,
  label,
  tone,
}: {
  icon: typeof Database;
  value: number;
  label: string;
  tone?: "accent" | "degraded";
}) {
  return (
    <div
      className={cn(
        "flex items-center gap-2 rounded-md border px-3 py-1.5",
        tone === "accent"
          ? "border-accent/30 bg-accent/5"
          : tone === "degraded"
            ? "border-degraded/40 bg-degraded/10"
            : "border-border bg-surface-raised/60",
      )}
    >
      <Icon className={cn("size-4", tone === "degraded" ? "text-degraded" : "text-muted-foreground")} />
      <span className="font-mono text-body-sm font-medium tabular-nums text-foreground">{value}</span>
      <span className="text-caption text-muted-foreground">{label}</span>
    </div>
  );
}

/** One source's coverage card: identity, counts, artifacts, counted gaps + scope links. */
function SourceCard({
  caseId,
  source,
  coverage,
  loading,
}: {
  caseId: string;
  source: SourceInfo;
  coverage: SourceCoverage | undefined;
  loading: boolean;
}) {
  const mismatch = hasLabelMismatch(source);
  const skip = coverage ? Object.entries(coverage.skip_counts ?? {}).filter(([, v]) => v > 0) : [];

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <Database className="size-4 text-accent" />
          <CardTitle className="min-w-0 break-words">{source.dc_label}</CardTitle>
          {source.is_global_catalog ? (
            <Badge variant="degraded" title="Holds partial read-only replicas of other domains">
              global catalog
            </Badge>
          ) : null}
        </div>
        <CardDescription className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="font-mono text-foreground">
            {source.domain_fqdn ?? source.domain_id ?? "domain not derived"}
          </span>
          <span className="text-muted-foreground">· forest {source.forest_id}</span>
        </CardDescription>
        {mismatch ? (
          <p className="flex items-start gap-1.5 text-caption text-degraded">
            <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
            <span>
              Declared <span className="font-mono">{source.declared_domain}</span> disagrees with the
              derived domain — the ntds.dit value is authoritative and is used for scoping.
            </span>
          </p>
        ) : null}
      </CardHeader>
      <CardContent className="space-y-3">
        {/* Object / edge counts per source */}
        <div className="flex flex-wrap gap-2">
          <MiniStat value={source.node_count} label="objects" />
          <MiniStat value={source.edge_count} label="edges" />
        </div>

        {/* Artifacts that produced this source */}
        {loading ? (
          <SkeletonRows rows={1} />
        ) : coverage && coverage.artifacts.length > 0 ? (
          <div className="space-y-1">
            <span className="eyebrow">Artifacts</span>
            <ul className="space-y-0.5">
              {coverage.artifacts.map((a) => (
                <li key={a.image_sha256 ?? a.source_file} className="flex items-center gap-2 text-micro">
                  <CheckCircle2 className="size-3 shrink-0 text-available" />
                  <span className="truncate font-mono text-foreground">{a.source_file ?? "artifact"}</span>
                  {a.image_sha256 ? (
                    <span className="shrink-0 font-mono tabular-nums text-muted-foreground" title={a.image_sha256}>
                      {shortSha(a.image_sha256)}
                    </span>
                  ) : null}
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {/* Counted gaps (honest degraded branches for this source) */}
        {skip.length > 0 ? (
          <div className="space-y-1">
            <span className="eyebrow text-degraded">Counted gaps</span>
            <ul className="space-y-0.5">
              {skip.map(([k, v]) => (
                <li key={k} className="flex items-start gap-1.5 text-micro text-muted-foreground">
                  <CircleSlash className="mt-0.5 size-3 shrink-0 text-degraded" />
                  <span>
                    <span className="font-mono tabular-nums text-degraded">{v}</span>{" "}
                    <span className="font-mono">{k}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {/* Per-source scoping: browse this source's entities standalone (M-MS2). */}
        <div className="flex flex-wrap gap-2 border-t border-border pt-3">
          <Button asChild size="sm" variant="secondary">
            <Link to={`/case/${encodeURIComponent(caseId)}/dossiers?source_id=${encodeURIComponent(source.source_id)}`}>
              <FileText className="size-4" /> Browse this source
            </Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function MiniStat({ value, label }: { value: number; label: string }) {
  return (
    <div className="flex items-baseline gap-1.5 rounded-md border border-border bg-surface-raised/60 px-2.5 py-1">
      <span className="font-mono text-body-sm font-medium tabular-nums text-foreground">
        {value.toLocaleString("en-US")}
      </span>
      <span className="text-micro text-muted-foreground">{label}</span>
    </div>
  );
}

/** The Phase-1 cross-domain honesty card — found relations vs counted gaps. */
function CrossDomainCard({
  signals,
  domains,
  forests,
  gcSources,
}: {
  signals: ReturnType<typeof crossDomainSignals>;
  domains: string[];
  forests: string[];
  gcSources: number;
}) {
  // Single-domain case with nothing cross-domain measured: say so plainly.
  if (signals.empty && signals.mismatches.length === 0 && domains.length <= 1 && gcSources === 0) {
    return null;
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Globe className="size-4 text-accent" /> Cross-domain relations
        </CardTitle>
        <CardDescription>
          {forests.length > 1 ? "Cross-forest case. " : null}
          Trusts, foreign-security-principals and sIDHistory bridges WRAITH wired — and every relation
          it could not fully resolve, counted. Same honesty polarity as the GPO / AD CS cards.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {signals.found.length > 0 ? (
          <SignalGroup
            title="Resolved"
            tone="available"
            icon={CheckCircle2}
            rows={signals.found}
          />
        ) : null}
        {signals.gaps.length > 0 ? (
          <SignalGroup title="Unresolved — counted" tone="degraded" icon={TriangleAlert} rows={signals.gaps} />
        ) : null}
        {signals.mismatches.length > 0 ? (
          <SignalGroup
            title="Declaration checks"
            tone="unavailable"
            icon={AlertTriangle}
            rows={signals.mismatches}
          />
        ) : null}
        {signals.empty && signals.mismatches.length === 0 ? (
          <p className="text-caption text-muted-foreground">
            No cross-domain relations were observed across these sources.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function SignalGroup({
  title,
  tone,
  icon: Icon,
  rows,
}: {
  title: string;
  tone: "available" | "degraded" | "unavailable";
  icon: typeof CheckCircle2;
  rows: Array<{ key: string; label: string; count: number }>;
}) {
  const toneText =
    tone === "available" ? "text-available" : tone === "degraded" ? "text-degraded" : "text-unavailable";
  return (
    <div className="space-y-1.5">
      <p className={cn("eyebrow", toneText)}>{title}</p>
      <ul className="space-y-1">
        {rows.map((r) => (
          <li key={r.key} className="flex items-start gap-2 text-body-sm">
            <Icon className={cn("mt-0.5 size-3.5 shrink-0", toneText)} />
            <span className="text-foreground-secondary">
              <span className={cn("font-mono tabular-nums", toneText)}>{r.count.toLocaleString("en-US")}</span>{" "}
              {r.label}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * Opt-in merge (now functional, M-MS4b) + the divergence report. OFF by default —
 * per-source-separate is the landing view above. Flipping it on folds the selected
 * sources and reads the divergence ledger, with the honest dormant-tier caveat.
 */
function MergePanel({ caseId, sources }: { caseId: string; sources: SourceInfo[] }) {
  const [report, setReport] = useState<MergeReport | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canMerge = sources.length >= 2;

  async function runMerge() {
    setRunning(true);
    setError(null);
    try {
      const res = await api.mergeSources(caseId, sources.map((s) => s.source_id));
      setReport(res);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setRunning(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="min-w-0">
            <CardTitle className="flex items-center gap-2">
              <GitMerge className="size-4 text-accent" /> Merge sources
            </CardTitle>
            <CardDescription>
              Reconcile the selected sources into one presented view + a counted divergence report.
              Nothing is dropped or fabricated; per-source copies are retained.
            </CardDescription>
          </div>
          <Button size="sm" disabled={!canMerge || running} onClick={() => void runMerge()}>
            {running ? <Loader2 className="size-4 animate-spin" /> : <GitMerge className="size-4" />}
            {report ? "Re-run merge" : "Merge sources"}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {!canMerge ? (
          <p className="flex items-start gap-1.5 text-caption text-muted-foreground">
            <TriangleAlert className="mt-0.5 size-3.5 shrink-0 text-degraded" />
            Merge needs at least two sources. Per-source-separate is the view for a single source.
          </p>
        ) : null}

        {error ? <p className="text-caption text-unavailable">{error}</p> : null}

        {report ? <MergeReportView caseId={caseId} report={report} /> : null}
      </CardContent>
    </Card>
  );
}

/** Known-dormant merge gaps → plain-English honest caveats (never over-claim). */
const MERGE_GAP_CAVEATS: Record<string, string> = {
  "merge.attid_map_not_provided":
    "Per-attribute newest-wins (tier-1) is dormant — no schema ATTID map is wired yet, so attributes resolve by object-level recency.",
  "merge.secret_fingerprints_not_computed":
    "Secret divergence was not evaluated this run — per-source secret fingerprinting is a separate integration. Absence here is not a claim of 'no secret divergence'.",
  "merge.no_merge_run": "No merge has run for this case yet.",
  "merge.presented_read_degraded":
    "A presented-value lookup failed and degraded to contested — the attribute is badged, never shown as the benign value.",
};

function MergeReportView({ caseId, report }: { caseId: string; report: MergeReport }) {
  const divQuery = useQuery<DivergenceLedger, ApiError>({
    queryKey: ["divergence", caseId, report.run_id],
    queryFn: () => api.divergence(caseId),
    enabled: !report.nothing_to_merge,
  });

  if (report.nothing_to_merge) {
    return (
      <p className="flex items-start gap-1.5 text-caption text-muted-foreground">
        <TriangleAlert className="mt-0.5 size-3.5 shrink-0 text-degraded" />
        Nothing to merge — fewer than two sources shared an object set. The per-source views above are
        the complete picture.
      </p>
    );
  }

  const caveats = Object.keys(report.counted_gaps).filter((k) => k in MERGE_GAP_CAVEATS);

  return (
    <div className="space-y-4">
      {/* Headline counts */}
      <div className="flex flex-wrap gap-2">
        <MiniStat value={report.nodes_reconciled} label="objects folded" />
        <MiniStat value={report.edges_reconciled} label="edges folded" />
      </div>

      {/* The "DC-A vs DC-B disagreed" report */}
      <DivergenceCard report={report} divergence={divQuery.data} loading={divQuery.isLoading} />

      {/* Honest dormant-tier caveats */}
      {caveats.length > 0 ? (
        <div className="space-y-1 rounded-md border border-degraded/30 bg-degraded/5 p-3">
          <p className="eyebrow text-degraded">What this merge does NOT do yet</p>
          <ul className="space-y-1">
            {caveats.map((k) => (
              <li key={k} className="flex items-start gap-1.5 text-caption text-foreground-secondary">
                <ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-degraded" />
                {MERGE_GAP_CAVEATS[k]}
              </li>
            ))}
          </ul>
          <p className="text-micro text-muted-foreground">
            The merge currently resolves by object-level recency (tier-2/3 of the resolution ladder);
            true ties are left contested and counted, never silently chosen.
          </p>
        </div>
      ) : null}
    </div>
  );
}

/** The divergence summary line + per-type drill-down (contract §3.4 / §6). */
function DivergenceCard({
  report,
  divergence,
  loading,
}: {
  report: MergeReport;
  divergence: DivergenceLedger | undefined;
  loading: boolean;
}) {
  const r = report.report;
  const parts: Array<{ label: string; count: number }> = [
    { label: "attributes", count: report.attribute_divergences },
    { label: "memberships", count: report.edge_membership_divergences },
    { label: "secrets", count: report.secret_divergences },
    { label: "deleted-on-one-DC", count: report.deleted_on_source },
    { label: "candidate lingering", count: report.candidate_lingering_objects },
  ];
  const anyDivergence = r.total > 0 || parts.some((p) => p.count > 0);

  return (
    <div className="space-y-2 rounded-md border border-border bg-surface-raised/40 p-3">
      <p className="eyebrow">Divergence report</p>
      {!anyDivergence ? (
        <p className="text-caption text-muted-foreground">
          The sources agreed — no attribute, membership, secret, or lifecycle divergence counted.
        </p>
      ) : (
        <p className="text-body-sm leading-relaxed text-foreground-secondary">
          These sources disagreed on{" "}
          {parts
            .filter((p) => p.count > 0)
            .map((p, i, arr) => (
              <span key={p.label}>
                <span className="font-mono tabular-nums text-foreground">{p.count}</span> {p.label}
                {i < arr.length - 1 ? ", " : ""}
              </span>
            ))}
          .
        </p>
      )}

      {report.attribute_unresolved > 0 ? (
        <p className="flex items-start gap-1.5 text-caption text-degraded">
          <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
          <span>
            <span className="font-mono tabular-nums">{report.attribute_unresolved}</span> attribute
            {report.attribute_unresolved === 1 ? "" : "s"} left contested (no tier resolved them) —
            presented with the safer reading and badged on the entity's dossier.
          </span>
        </p>
      ) : null}

      {/* Ledger drill-down rows */}
      {loading ? (
        <SkeletonRows rows={1} />
      ) : divergence && divergence.rows.length > 0 ? (
        <details className="group">
          <summary className="cursor-pointer list-none text-caption text-accent hover:underline">
            View {divergence.rows.length} ledger row{divergence.rows.length === 1 ? "" : "s"}
          </summary>
          <ul className="mt-2 space-y-1">
            {divergence.rows.slice(0, 50).map((row, i) => (
              <li
                key={`${row.obj_id}:${row.attribute ?? ""}:${i}`}
                className="rounded border border-border/60 bg-surface p-2 text-micro"
              >
                <div className="flex flex-wrap items-center gap-1.5">
                  <Badge variant="outline">{row.divergence_type}</Badge>
                  {row.attribute ? (
                    <span className="font-mono text-foreground">{row.attribute}</span>
                  ) : null}
                  <Badge variant={row.resolution === "unresolved" || !row.resolution ? "unavailable" : "degraded"}>
                    {row.resolution ?? "unresolved"}
                  </Badge>
                  {row.resolved_by ? (
                    <span className="text-muted-foreground">by {row.resolved_by}</span>
                  ) : null}
                </div>
                <p className="mt-1 truncate font-mono text-muted-foreground" title={row.obj_id}>
                  {row.obj_id}
                </p>
              </li>
            ))}
          </ul>
          {divergence.rows.length > 50 ? (
            <p className="mt-1 text-micro text-muted-foreground">
              Showing 50 of {divergence.rows.length} rows.
            </p>
          ) : null}
        </details>
      ) : null}
    </div>
  );
}
