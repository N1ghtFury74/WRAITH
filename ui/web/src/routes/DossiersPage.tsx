import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronUp, FileText, Layers, Printer, Search, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/states";
import {
  api,
  ApiError,
  type CaseSummary,
  type NodeListPage,
  type NodeSort,
  type SortOrder,
} from "@/lib/api";
import { errorText } from "@/lib/reasons";
import { kindColor } from "@/lib/graph/encoding";
import { cn } from "@/lib/utils";

const PAGE = 50;

export function DossiersPage() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  // Optional per-source scope (M-MS2): browse ONE source's objects standalone.
  const sourceId = searchParams.get("source_id") ?? undefined;
  const scopeSuffix = sourceId ? `?source_id=${encodeURIComponent(sourceId)}` : "";

  const [kind, setKind] = useState<string | undefined>(undefined);
  const [q, setQ] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");
  const [sort, setSort] = useState<NodeSort>("name");
  const [order, setOrder] = useState<SortOrder>("asc");
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    const t = window.setTimeout(() => setDebouncedQ(q.trim()), 300);
    return () => window.clearTimeout(t);
  }, [q]);

  // Reset paging when the filter/sort changes.
  useEffect(() => setOffset(0), [kind, debouncedQ, sort, order]);

  const summaryQuery = useQuery<CaseSummary, ApiError>({
    queryKey: ["summary", caseId, sourceId],
    queryFn: () => api.summary(caseId as string, sourceId),
    enabled: Boolean(caseId),
    retry: false,
  });

  const listQuery = useQuery<NodeListPage, ApiError>({
    queryKey: ["nodes", caseId, sourceId, kind, debouncedQ, sort, order, offset],
    queryFn: () =>
      api.nodesPage(
        caseId as string,
        { kind, q: debouncedQ || undefined, sort, order, limit: PAGE, offset },
        sourceId,
      ),
    enabled: Boolean(caseId) && summaryQuery.isSuccess,
  });

  const tabs = useMemo(() => {
    const counts = summaryQuery.data?.node_kind_counts ?? {};
    const entries = Object.entries(counts).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const total = entries.reduce((n, [, c]) => n + c, 0);
    return { entries, total };
  }, [summaryQuery.data]);

  function toggleSort(col: NodeSort) {
    if (sort === col) setOrder((o) => (o === "asc" ? "desc" : "asc"));
    else {
      setSort(col);
      setOrder(col === "risk" || col === "tier" ? "desc" : "asc");
    }
  }

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
          message={notReady ? "Run analysis first to browse entities." : errorText(summaryQuery.error)}
          action={
            <Button asChild size="sm" variant="secondary">
              <Link to={`/case/${encodeURIComponent(caseId)}/ingest`}>Go to Case &amp; Ingest</Link>
            </Button>
          }
        />
      </div>
    );
  }

  const page = listQuery.data;
  const sortIcon = (col: NodeSort) =>
    sort === col ? (order === "asc" ? <ChevronUp className="inline size-3" /> : <ChevronDown className="inline size-3" />) : null;

  return (
    <div className="mx-auto max-w-6xl space-y-4 p-4 sm:p-5">
      <div className="flex flex-wrap items-center gap-2">
        <FileText className="size-5 text-accent" />
        <h1 className="text-display tracking-tight">Dossiers</h1>
        <span className="text-body text-muted-foreground">
          the per-entity context behind the graph — browse by type
        </span>
        {kind ? (
          <Button asChild size="sm" variant="secondary" className="ml-auto">
            <Link to={`/case/${encodeURIComponent(caseId)}/dossier/print?kind=${encodeURIComponent(kind)}`}>
              <Printer className="size-4" /> Print all {kind}
            </Link>
          </Button>
        ) : null}
      </div>

      {/* Per-source scope banner — honest, with a one-click exit. */}
      {sourceId ? (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-accent/30 bg-accent/5 px-3 py-2 text-caption">
          <Layers className="size-4 shrink-0 text-accent" />
          <span className="text-foreground-secondary">
            Scoped to one source — showing only{" "}
            <span className="font-mono text-foreground">{sourceId.slice(0, 12)}…</span>'s objects. No
            merge overlay is applied in this view.
          </span>
          <Button asChild size="xs" variant="secondary" className="ml-auto">
            <Link to={`/case/${encodeURIComponent(caseId)}/dossiers`}>
              <X className="size-3" /> Exit scope
            </Link>
          </Button>
        </div>
      ) : null}

      {/* Kind tabs (live from node_kind_counts) */}
      {summaryQuery.isLoading ? (
        <SkeletonRows rows={1} />
      ) : (
        <div className="flex flex-wrap gap-1.5">
          <KindTab label="All" count={tabs.total} active={kind === undefined} onClick={() => setKind(undefined)} />
          {tabs.entries.map(([k, c]) => (
            <KindTab key={k} label={k} count={c} dot={kindColor(k)} active={kind === k} onClick={() => setKind(k)} />
          ))}
        </div>
      )}

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by name / SID / DN" className="pl-9" />
      </div>

      {/* Table */}
      <div className="overflow-hidden rounded-lg border border-border">
        <table className="w-full text-left text-body-sm">
          <thead className="bg-surface-raised/50 text-muted-foreground">
            <tr>
              <SortTh label="Name" onClick={() => toggleSort("name")}>{sortIcon("name")}</SortTh>
              <SortTh label="Kind" onClick={() => toggleSort("kind")}>{sortIcon("kind")}</SortTh>
              <SortTh label="Tier" onClick={() => toggleSort("tier")}>{sortIcon("tier")}</SortTh>
              <SortTh label="Risk" onClick={() => toggleSort("risk")}>{sortIcon("risk")}</SortTh>
            </tr>
          </thead>
          <tbody>
            {listQuery.isLoading ? (
              <tr>
                <td colSpan={4} className="p-4">
                  <SkeletonRows rows={5} />
                </td>
              </tr>
            ) : listQuery.error ? (
              <tr>
                <td colSpan={4} className="p-4">
                  <ErrorState message={errorText(listQuery.error)} />
                </td>
              </tr>
            ) : page && page.entries.length > 0 ? (
              page.entries.map((e) => (
                <tr
                  key={e.node_id}
                  onClick={() => navigate(`/case/${encodeURIComponent(caseId)}/dossier/${encodeURIComponent(e.node_id)}${scopeSuffix}`)}
                  className="cursor-pointer border-t border-border/60 hover:bg-surface-raised/40"
                >
                  <td className="px-3 py-2">
                    <span className="flex items-center gap-2">
                      <span className="size-2 shrink-0 rounded-full" style={{ backgroundColor: kindColor(e.kind) }} />
                      <span className="truncate font-mono text-foreground">{e.label}</span>
                      {e.highvalue ? <Badge variant="unavailable">Tier-0</Badge> : null}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">{e.kind}</td>
                  <td className="px-3 py-2 font-mono tabular-nums text-muted-foreground">
                    {e.tier === null ? "—" : e.tier}
                  </td>
                  <td className="px-3 py-2 font-mono tabular-nums text-foreground">
                    {e.risk_score === null ? "—" : e.risk_score}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={4} className="p-4">
                  <EmptyState title="No entities" hint="No entities match this type/filter." />
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Footer: honest count + pagination */}
      {page ? (
        <div className="flex items-center gap-3 text-caption text-muted-foreground">
          <span>
            <span className="font-mono tabular-nums text-foreground">
              {page.offset + 1}–{page.offset + page.returned}
            </span>{" "}
            of <span className="font-mono tabular-nums text-foreground">{page.total_matched}</span>
            {page.truncated ? " (more — page forward)" : ""}
          </span>
          <div className="ml-auto flex items-center gap-2">
            <Button size="sm" variant="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
              Prev
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={offset + page.returned >= page.total_matched}
              onClick={() => setOffset(offset + PAGE)}
            >
              Next
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function KindTab({
  label,
  count,
  active,
  dot,
  onClick,
}: {
  label: string;
  count: number;
  active: boolean;
  dot?: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center gap-2 rounded-md border px-3 py-1.5 text-caption transition-colors duration-150 focus-visible:ring-1 focus-visible:ring-ring",
        active
          ? "border-accent/50 bg-accent/15 text-accent"
          : "border-border text-muted-foreground hover:bg-surface-raised hover:text-foreground",
      )}
    >
      {dot ? <span className="size-2 rounded-full" style={{ backgroundColor: dot }} /> : null}
      {label}
      <span className="font-mono text-micro tabular-nums text-muted-foreground">{count}</span>
    </button>
  );
}

function SortTh({ label, onClick, children }: { label: string; onClick: () => void; children?: React.ReactNode }) {
  return (
    <th className="px-3 py-2 font-medium">
      <button onClick={onClick} className="flex items-center gap-1 hover:text-foreground focus-visible:ring-1 focus-visible:ring-ring">
        {label} {children}
      </button>
    </th>
  );
}
