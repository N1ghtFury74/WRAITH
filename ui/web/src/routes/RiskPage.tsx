import { useQuery } from "@tanstack/react-query";
import { Info, Loader2, Printer, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState, ErrorState } from "@/components/ui/states";
import { api, ApiError, type NodeRisk, type RiskSummary } from "@/lib/api";
import { errorText } from "@/lib/reasons";
import { kindColor } from "@/lib/graph/encoding";
import { cn } from "@/lib/utils";

const TILES: Array<{ key: keyof RiskSummary; label: string }> = [
  { key: "tier0_nodes", label: "Tier-0 nodes" },
  { key: "dcsync_holders", label: "DCSync holders" },
  { key: "tier0_reachable", label: "Tier-0 reachable" },
  { key: "unconstrained_delegation", label: "Unconstrained deleg" },
  { key: "kerberoastable", label: "Kerberoastable" },
  { key: "asrep_roastable", label: "AS-REP roastable" },
  { key: "has_sid_history", label: "Has SID history" },
  { key: "scored_nodes", label: "Scored nodes" },
];

export function RiskPage() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const [kindFilter, setKindFilter] = useState<string | null>(null);

  const summaryQuery = useQuery<RiskSummary, ApiError>({
    queryKey: ["risk-summary", caseId],
    queryFn: () => api.riskSummary(caseId as string, 10),
    enabled: Boolean(caseId),
    retry: false,
  });
  const nodesQuery = useQuery<NodeRisk[], ApiError>({
    queryKey: ["risk-nodes", caseId],
    queryFn: () => api.riskNodes(caseId as string, { limit: 200, min_score: 1 }),
    enabled: Boolean(caseId) && summaryQuery.isSuccess,
  });

  const nodes = useMemo(() => nodesQuery.data ?? [], [nodesQuery.data]);
  const kinds = useMemo(
    () => [...new Set(nodes.map((n) => n.kind))].sort(),
    [nodes],
  );
  const filtered = useMemo(
    () => (kindFilter ? nodes.filter((n) => n.kind === kindFilter) : nodes),
    [nodes, kindFilter],
  );
  const chart = useMemo(() => filtered.slice(0, 10), [filtered]);
  const maxScore = chart[0]?.score ?? 1;

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
          title={notReady ? "Case not analyzed yet" : "Failed to load risk"}
          message={notReady ? "Run analysis first." : errorText(summaryQuery.error)}
          action={
            <Button asChild size="sm" variant="secondary">
              <Link to={`/case/${encodeURIComponent(caseId)}/ingest`}>Go to Case &amp; Ingest</Link>
            </Button>
          }
        />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl space-y-4 p-4 sm:p-5">
      <div className="flex flex-wrap items-center gap-2">
        <ShieldAlert className="size-5 text-accent" />
        <h1 className="text-display tracking-tight">Risk</h1>
        <Button asChild size="sm" variant="secondary" className="ml-auto">
          <Link to={`/case/${encodeURIComponent(caseId)}/dossier/print?preset=tier0`}>
            <Printer className="size-4" /> Print all Tier-0
          </Link>
        </Button>
      </div>

      <p className="text-body text-muted-foreground">
        Where to start the hunt: the principals and objects with the most standing privilege and the
        shortest reach to Tier-0, ranked. Open any row for its full dossier.
      </p>

      <p className="flex items-center gap-1.5 text-caption text-muted-foreground">
        <Info className="size-3.5" /> Risk scoring covers security principals and the Domain object only.
        Browse OUs / GPOs / containers under Dossiers.
      </p>

      {/* Transparency note: the score is a deterministic sum of named factor weights
          (wraith/api/risk.py) — never AI/ML. Each dossier itemizes which factors
          fired and their weights; the ranking is a starting point, not a verdict. */}
      <p className="rounded-md border border-border bg-surface-raised/50 px-3 py-2 text-caption leading-relaxed text-muted-foreground">
        Scores are a <span className="text-foreground">transparent rule-based sum</span> of named
        factor weights — not AI or ML. Every score opens to the exact factors that fired and their
        weights in the entity dossier. Treat the ranking as where to look first, and verify before
        acting.
      </p>

      {/* Headline tiles */}
      {summaryQuery.isLoading || !summaryQuery.data ? (
        <div className="flex items-center gap-2 py-6 text-body text-muted-foreground">
          <Loader2 className="size-4 animate-spin" /> Loading risk summary…
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {TILES.map((t) => (
            <Card key={t.key}>
              <CardContent className="p-3">
                <p className="eyebrow">{t.label}</p>
                <p className="mt-1 font-mono text-hero tabular-nums text-foreground">
                  {summaryQuery.data![t.key] as number}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Top-N CSS bar chart */}
      {chart.length > 0 ? (
        <Card>
          <CardContent className="space-y-1.5 p-4">
            <p className="eyebrow mb-2">Top {chart.length} by score{kindFilter ? ` · ${kindFilter}` : ""}</p>
            {chart.map((n) => (
              <button
                key={n.node_id}
                onClick={() => navigate(`/case/${encodeURIComponent(caseId)}/dossier/${encodeURIComponent(n.node_id)}`)}
                className="flex w-full items-center gap-2 text-left text-caption focus-visible:ring-1 focus-visible:ring-ring"
              >
                <span className="w-40 shrink-0 truncate font-mono text-foreground" title={n.label}>{n.label}</span>
                <span className="relative h-3.5 flex-1 overflow-hidden rounded bg-muted">
                  <span
                    className="absolute inset-y-0 left-0 rounded"
                    style={{ width: `${Math.max(3, (n.score / maxScore) * 100)}%`, backgroundColor: kindColor(n.kind) }}
                  />
                </span>
                <span className="w-8 shrink-0 text-right font-mono tabular-nums text-foreground">{n.score}</span>
              </button>
            ))}
          </CardContent>
        </Card>
      ) : null}

      {/* Kind filter */}
      {kinds.length > 1 ? (
        <div className="flex flex-wrap gap-1.5">
          <FilterChip label="All" active={kindFilter === null} onClick={() => setKindFilter(null)} />
          {kinds.map((k) => (
            <FilterChip key={k} label={k} dot={kindColor(k)} active={kindFilter === k} onClick={() => setKindFilter(k)} />
          ))}
        </div>
      ) : null}

      {/* Ranked table */}
      <div className="overflow-hidden rounded-lg border border-border">
        <table className="w-full text-left text-body-sm">
          <thead className="bg-surface-raised/50 text-muted-foreground">
            <tr>
              <th className="px-3 py-2 font-medium">Score</th>
              <th className="px-3 py-2 font-medium">Name</th>
              <th className="px-3 py-2 font-medium">Kind</th>
              <th className="px-3 py-2 font-medium">Tier</th>
              <th className="px-3 py-2 font-medium">Top factors</th>
            </tr>
          </thead>
          <tbody>
            {nodesQuery.isLoading ? (
              <tr>
                <td colSpan={5} className="p-6 text-center text-body text-muted-foreground">
                  <Loader2 className="mx-auto size-4 animate-spin" />
                </td>
              </tr>
            ) : filtered.length > 0 ? (
              filtered.map((n) => (
                <tr
                  key={n.node_id}
                  onClick={() => navigate(`/case/${encodeURIComponent(caseId)}/dossier/${encodeURIComponent(n.node_id)}`)}
                  className="cursor-pointer border-t border-border/60 hover:bg-surface-raised/40"
                >
                  <td className="px-3 py-2 font-mono tabular-nums text-foreground">{n.score}</td>
                  <td className="px-3 py-2">
                    <span className="flex items-center gap-2">
                      <span className="size-2 shrink-0 rounded-full" style={{ backgroundColor: kindColor(n.kind) }} />
                      <span className="truncate font-mono text-foreground">{n.label}</span>
                      {n.tier === 0 ? <Badge variant="unavailable">Tier-0</Badge> : null}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">{n.kind}</td>
                  <td className="px-3 py-2 font-mono tabular-nums text-muted-foreground">{n.tier === null ? "—" : n.tier}</td>
                  {/* Itemized top factors with their weights — the score is never a
                      black box. The full breakdown (all factors + total) is one click
                      away in the dossier this row opens. */}
                  <td className="px-3 py-2">
                    {n.factors.length === 0 ? (
                      <span className="text-muted-foreground">—</span>
                    ) : (
                      <div
                        className="flex flex-wrap items-center gap-1"
                        title={n.factors.map((f) => `${f.label} +${f.weight}`).join(", ")}
                      >
                        {n.factors.slice(0, 3).map((f) => (
                          <span
                            key={f.code}
                            className="inline-flex items-center gap-1 rounded border border-border bg-surface-raised/60 px-1.5 py-0.5 text-micro text-muted-foreground"
                          >
                            {f.label}
                            <span className="font-mono tabular-nums text-foreground">+{f.weight}</span>
                          </span>
                        ))}
                        {n.factors.length > 3 ? (
                          <span className="text-micro tabular-nums text-muted-foreground">
                            +{n.factors.length - 3} more
                          </span>
                        ) : null}
                      </div>
                    )}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={5} className="p-4">
                  <EmptyState title="No scored nodes" hint="No principals scored at or above the minimum." />
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function FilterChip({ label, active, dot, onClick }: { label: string; active: boolean; dot?: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-caption transition-colors duration-150 focus-visible:ring-1 focus-visible:ring-ring",
        active ? "border-accent/50 bg-accent/15 text-accent" : "border-border text-muted-foreground hover:bg-surface-raised",
      )}
    >
      {dot ? <span className="size-2 rounded-full" style={{ backgroundColor: dot }} /> : null}
      {label}
    </button>
  );
}
