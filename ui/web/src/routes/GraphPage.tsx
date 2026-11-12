import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  CheckCircle2,
  Frame,
  List,
  Loader2,
  Maximize2,
  Minimize2,
  Network,
  RotateCcw,
  SlidersHorizontal,
  Spline,
  Tags,
  Undo2,
  Zap,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { ConnectorPanel } from "@/components/graph/ConnectorPanel";
import { FilterRail, DEFAULT_FILTERS, type GraphFilters } from "@/components/graph/FilterRail";
import { GraphList } from "@/components/graph/GraphList";
import { Inspector } from "@/components/graph/Inspector";
import { Legend } from "@/components/graph/Legend";
import {
  NodeContextMenu,
  type ContextNode,
  type NodeAction,
} from "@/components/graph/NodeContextMenu";
import { PathForm } from "@/components/graph/PathForm";
import { PathResultPanel } from "@/components/graph/PathResultPanel";
import { SigmaCanvas } from "@/components/graph/SigmaCanvas";
import { HunterLibrary } from "@/components/shell/HunterLibrary";
import { SecondaryPanel } from "@/components/shell/SecondaryPanel";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, Skeleton, SkeletonRows } from "@/components/ui/states";
import {
  api,
  ApiError,
  type CaseSummary,
  type ConnectorResult,
  type GraphSlice,
  type NodeRef,
  type PathRequest,
  type PathResult,
  type PrebuiltQuery,
  type SliceRequest,
} from "@/lib/api";
import { applyCollapse, removableNodeIds, type WalkStep } from "@/lib/graph/collapse";
import { connectorUnionSlice, viaNodeSet } from "@/lib/graph/connector";
import { showAllEdgeLabelGate } from "@/lib/graph/interactions";
import { mergeSlices, newNodeCount, WALK_NODE_CAP } from "@/lib/graph/merge";
import { pathIsolation, pathUnionSlice } from "@/lib/graph/paths";
import { errorText } from "@/lib/reasons";
import { cn } from "@/lib/utils";
import { useTheme } from "@/hooks/useTheme";
import { useLiveRun } from "@/store/run";

const SLICE_LIMIT = 1000;

type PathView = { kind: "path"; title: string; result: PathResult; gaps: Record<string, number> };
type SetView = { kind: "set"; title: string; slice: GraphSlice; gaps: Record<string, number> };
type AnalysisView = PathView | SetView | null;

interface PathForm {
  start: NodeRef | null;
  end: NodeRef | null;
}

function toBody(filters: GraphFilters): SliceRequest {
  return {
    seed_node_ids: filters.seed ? [filters.seed.node_id] : null,
    node_kinds: filters.nodeKinds.size ? [...filters.nodeKinds].sort() : null,
    edge_kinds: filters.edgeKinds.size ? [...filters.edgeKinds].sort() : null,
    tier0_only: filters.tier0Only,
    depth: filters.seed ? filters.depth : 1,
    limit: SLICE_LIMIT,
    layout: "auto",
  };
}

/** The user has set an explicit filter (not merely the default view). */
function explicitFilter(f: GraphFilters): boolean {
  return f.nodeKinds.size > 0 || f.edgeKinds.size > 0 || f.tier0Only || f.seed !== null;
}

/** Compact icon toggle used in the canvas toolbar. */
function ToolToggle({
  active,
  title,
  onClick,
  children,
}: {
  active?: boolean;
  title: string;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      title={title}
      aria-pressed={active}
      onClick={onClick}
      className={cn(
        "flex size-8 items-center justify-center rounded-md border border-border shadow-overlay backdrop-blur transition-colors",
        active
          ? "border-accent/40 bg-accent/15 text-accent"
          : "bg-surface-overlay/95 text-muted-foreground hover:text-foreground",
      )}
    >
      {children}
    </button>
  );
}

function NotReady({ caseId, analyzing }: { caseId: string; analyzing: boolean }) {
  return (
    <div className="p-6">
      <div className="mb-4 flex items-center gap-2">
        <Network className="size-5 text-accent" />
        <h1 className="text-display">Capability Graph</h1>
      </div>
      <EmptyState
        icon={analyzing ? Loader2 : Network}
        title={analyzing ? "Analysis in progress…" : "Ready once a case is analyzed"}
        hint={
          analyzing
            ? "The graph loads automatically when the run completes."
            : "The capability graph maps the privilege terrain — who can reach Tier-0 and the paths between. Upload artifacts and run analysis to build it."
        }
        action={
          <Button asChild size="sm" variant="secondary">
            <Link to={`/case/${encodeURIComponent(caseId)}/ingest`}>Go to Case &amp; Ingest</Link>
          </Button>
        }
      />
    </div>
  );
}

export function GraphPage() {
  const { caseId } = useParams();
  const live = useLiveRun(caseId);
  const { resolvedTheme } = useTheme();
  // The active hunt is deep-linked via ?hunt=<query_id> (set by the sidebar
  // Hunter Library). GraphPage is the single owner of running it in the canvas.
  const [searchParams, setSearchParams] = useSearchParams();
  const huntParam = searchParams.get("hunt");
  const [filters, setFilters] = useState<GraphFilters>(DEFAULT_FILTERS);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const [analysis, setAnalysis] = useState<AnalysisView>(null);
  const [activeQueryId, setActiveQueryId] = useState<string | null>(null);
  const [isolatedIndex, setIsolatedIndex] = useState<number | null>(null);
  const [pathForm, setPathForm] = useState<PathForm>({ start: null, end: null });
  const [runningQueryId, setRunningQueryId] = useState<string | null>(null);
  const [pathRunning, setPathRunning] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [menu, setMenu] = useState<{ node: ContextNode; x: number; y: number } | null>(null);

  // Interactive walk: the working slice grows as you click nodes to expand.
  const [walk, setWalk] = useState<GraphSlice | null>(null);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [walkNote, setWalkNote] = useState<string | null>(null);
  // Ordered stack of expansion steps (seed + the node ids that step introduced) so
  // Walk Back / Collapse can remove exactly that step's uniquely-introduced leaves.
  const [walkSteps, setWalkSteps] = useState<WalkStep[]>([]);
  // True only for the render that follows an expansion (so the canvas preserves
  // node positions). Fresh views (base load, filter, reset, analysis) set false.
  const [expandMode, setExpandMode] = useState(false);

  // Connect-the-dots reveal (a slice with >=2 kinds but 0 edges → connecting chains).
  const [connector, setConnector] = useState<ConnectorResult | null>(null);
  const [connectorRunning, setConnectorRunning] = useState(false);

  // View chrome.
  const [focusMode, setFocusMode] = useState(false); // full-screen canvas
  const [showList, setShowList] = useState(false); // results List view beside the canvas
  const [showAllLabels, setShowAllLabels] = useState(false);
  // Bump to trigger a zoom-to-fit on the canvas (full-screen enter, "Fit" button).
  const [fitSignal, setFitSignal] = useState(0);

  const summaryQuery = useQuery<CaseSummary, ApiError>({
    queryKey: ["summary", caseId],
    queryFn: () => api.summary(caseId as string),
    enabled: Boolean(caseId),
    retry: false,
  });
  const ready = summaryQuery.isSuccess;

  // Prebuilt-query catalog (shared cache with the sidebar Hunter Library). Used
  // here only to resolve a ?hunt=<id> deep link to the query object to run.
  const queriesQuery = useQuery<PrebuiltQuery[]>({
    queryKey: ["analysis-queries", caseId],
    queryFn: () => api.listQueries(caseId as string),
    enabled: Boolean(caseId) && ready,
  });

  const structuralCount = useMemo(() => {
    const counts = summaryQuery.data?.node_kind_counts ?? {};
    return (counts.Container ?? 0) + (counts.Base ?? 0) + (counts.OUContainer ?? 0);
  }, [summaryQuery.data]);

  // First screen = the edge-rich Tier-0 neighbourhood (/graph/default). Any
  // explicit filter OR the structure toggle routes to a refined server slice.
  const refined = explicitFilter(filters) || filters.showStructure;
  const body = useMemo(() => toBody(filters), [filters]);

  const defaultQuery = useQuery({
    queryKey: ["graph-default", caseId],
    queryFn: () => api.graphDefault(caseId as string),
    enabled: Boolean(caseId) && ready && !refined,
    placeholderData: keepPreviousData,
  });
  const sliceQuery = useQuery({
    queryKey: ["slice", caseId, body],
    queryFn: () => api.slice(caseId as string, body),
    enabled: Boolean(caseId) && ready && refined,
    placeholderData: keepPreviousData,
  });

  const baseSlice = refined ? sliceQuery.data : defaultQuery.data;
  const baseFetching = refined ? sliceQuery.isFetching : defaultQuery.isFetching;
  const baseError = refined ? sliceQuery.error : defaultQuery.error;

  // A fresh base (new default/filter) resets the walk to that starting point.
  useEffect(() => {
    if (baseSlice) {
      setWalk(baseSlice);
      setExpandedIds(new Set());
      setWalkSteps([]);
      setWalkNote(null);
      setExpandMode(false);
      setConnector(null);
    }
  }, [baseSlice]);

  // Re-frame the canvas when entering full screen (the slice doesn't change, so a
  // fit signal is the trigger — the canvas auto-fits on every rebuild otherwise).
  useEffect(() => {
    if (focusMode) setFitSignal((s) => s + 1);
  }, [focusMode]);

  // The slice actually rendered + its variant/isolation + any "via" intermediates.
  const canvas: { slice: GraphSlice | undefined; variant: "graph" | "path"; via?: Set<string> } =
    useMemo(() => {
      if (connector && connector.paths.length > 0)
        return { slice: connectorUnionSlice(connector), variant: "path", via: viaNodeSet(connector) };
      if (analysis?.kind === "path") return { slice: pathUnionSlice(analysis.result), variant: "path" };
      if (analysis?.kind === "set") return { slice: analysis.slice, variant: "graph" };
      return { slice: walk ?? baseSlice, variant: "graph" };
    }, [connector, analysis, walk, baseSlice]);

  // "Show all labels" is honest: past the visible-edge cap it falls back to
  // focus-only labels and states why (research 08 §2.2).
  const showAllGate = useMemo(
    () => showAllEdgeLabelGate(canvas.slice?.edges.length ?? 0),
    [canvas.slice],
  );
  const effectiveShowAll = showAllLabels && showAllGate.allowed;

  const isolate = useMemo(() => {
    if (analysis?.kind === "path" && isolatedIndex !== null) {
      return pathIsolation(analysis.result.paths[isolatedIndex]);
    }
    return null;
  }, [analysis, isolatedIndex]);

  const nodeIndex = useMemo(() => {
    const m = new Map<string, NodeRef>();
    for (const n of canvas.slice?.nodes ?? []) m.set(n.node_id, { node_id: n.node_id, kind: n.kind, label: n.label });
    return m;
  }, [canvas.slice]);

  // Latest-ref to runQuery (a hoisted function declaration below) so the ?hunt=
  // auto-run effect can call it without taking its (per-render) identity as a dep.
  const runQueryRef = useRef<(q: PrebuiltQuery) => void>(() => {});
  runQueryRef.current = runQuery;

  // Deep link: when ?hunt=<id> names a supported, not-already-active hunt, run it
  // in the canvas. The sidebar Hunter Library drives this by setting the param.
  useEffect(() => {
    if (!huntParam || !ready || huntParam === activeQueryId) return;
    const q = queriesQuery.data?.find((x) => x.id === huntParam);
    if (!q || !q.supported) return;
    runQueryRef.current(q);
  }, [huntParam, queriesQuery.data, activeQueryId, ready]);

  /** Drop the ?hunt= deep link (on reset / leaving a hunt view) without a history push. */
  function clearHuntParam() {
    if (!huntParam) return;
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete("hunt");
        return next;
      },
      { replace: true },
    );
  }

  function resetView() {
    setAnalysis(null);
    setActiveQueryId(null);
    setIsolatedIndex(null);
    setAnalysisError(null);
    setSelectedId(null);
    setWalk(null);
    setExpandedIds(new Set());
    setWalkSteps([]);
    setWalkNote(null);
    setExpandMode(false);
    setConnector(null);
    setFilters(DEFAULT_FILTERS);
    clearHuntParam();
  }

  /** Click a node → pull its neighbours into the canvas (walk the graph). */
  async function expandNode(id: string) {
    if (!caseId || analysis || connector) return; // expansion is for the explore view
    if (expandedIds.has(id)) return;
    const current = walk ?? baseSlice;
    if (!current) return;
    if (current.nodes.length >= WALK_NODE_CAP) {
      setWalkNote(`View is full (${WALK_NODE_CAP} nodes). Reset to walk from a new start.`);
      return;
    }
    const NEIGHBOR_LIMIT = 200;
    setExpandedIds((p) => new Set(p).add(id));
    try {
      const nb = await api.neighbors(caseId, id, { depth: 1, limit: NEIGHBOR_LIMIT });
      const grew = newNodeCount(current, nb);
      if (grew === 0) {
        setWalkNote("No further relationships from this entity.");
        return;
      }
      if (current.nodes.length + grew > WALK_NODE_CAP) {
        setWalkNote(`Stopped at ${WALK_NODE_CAP} nodes — reset to walk from a new start.`);
        return;
      }
      // Honesty: a highly-connected node's neighbourhood is capped — never silent.
      setWalkNote(
        nb.truncated
          ? `Showing ${NEIGHBOR_LIMIT} of ${nb.total_matched} neighbours — some relationships not shown.`
          : null,
      );
      // Record which node ids THIS expansion introduced (for Walk Back / Collapse).
      const have = new Set(current.nodes.map((n) => n.node_id));
      const introduced = nb.nodes.map((n) => n.node_id).filter((nid) => !have.has(nid));
      setWalkSteps((prev) => [...prev, { seedId: id, introduced }]);
      setExpandMode(true);
      setWalk((prev) => mergeSlices(prev ?? current, nb));
    } catch (err) {
      setWalkNote(errorText(err));
    }
  }

  /** Walk Back: undo the last expansion, removing only the leaves it uniquely added. */
  function walkBack() {
    if (walkSteps.length === 0) return;
    const current = walk ?? baseSlice;
    const baseIds = baseSlice?.nodes.map((n) => n.node_id) ?? [];
    const last = walkSteps.length - 1;
    const removable = removableNodeIds(walkSteps, last, baseIds);
    const seedLabel = nodeIndex.get(walkSteps[last].seedId)?.label ?? "last step";
    setWalkSteps((prev) => prev.slice(0, -1));
    setExpandedIds((prev) => {
      const next = new Set(prev);
      next.delete(walkSteps[last].seedId);
      return next;
    });
    setExpandMode(false);
    if (current) setWalk(applyCollapse(current, removable));
    setWalkNote(`Collapsed ${removable.size} node${removable.size === 1 ? "" : "s"} from ${seedLabel}.`);
    setFitSignal((s) => s + 1);
  }

  /** Connect-the-dots: compute the minimal connecting chains for the retained set. */
  async function runConnector() {
    const current = canvas.slice;
    if (!caseId || !current) return;
    setConnectorRunning(true);
    setAnalysisError(null);
    try {
      const result = await api.connector(caseId, {
        node_ids: current.nodes.map((n) => n.node_id),
        max_hops: 6,
        max_paths: 12,
        max_pairs: 12,
      });
      setSelectedId(null);
      setConnector(result);
      setFitSignal((s) => s + 1);
    } catch (err) {
      setAnalysisError(errorText(err));
    } finally {
      setConnectorRunning(false);
    }
  }

  async function runPath(req: PathRequest, title: string) {
    if (!caseId) return;
    setPathRunning(true);
    setAnalysisError(null);
    try {
      const result = await api.paths(caseId, { max_hops: 8, max_paths: 25, ...req });
      setSelectedId(null);
      setIsolatedIndex(null);
      setActiveQueryId(null);
      setExpandMode(false);
      setConnector(null);
      setAnalysis({ kind: "path", title, result, gaps: {} });
    } catch (err) {
      setAnalysisError(errorText(err));
    } finally {
      setPathRunning(false);
    }
  }

  async function runQuery(q: PrebuiltQuery) {
    if (!caseId || !q.supported) return;
    setRunningQueryId(q.id);
    setAnalysisError(null);
    try {
      const res = await api.runQuery(caseId, q.id, { max_hops: 8, max_paths: 25 });
      setSelectedId(null);
      setIsolatedIndex(null);
      setExpandMode(false);
      setConnector(null);
      setActiveQueryId(q.id);
      if (res.kind === "path" && res.paths) {
        setAnalysis({ kind: "path", title: q.label, result: res.paths, gaps: res.counted_gaps });
      } else if (res.slice) {
        setAnalysis({ kind: "set", title: q.label, slice: res.slice, gaps: res.counted_gaps });
      }
    } catch (err) {
      setAnalysisError(errorText(err));
    } finally {
      setRunningQueryId(null);
    }
  }

  function onMenuAction(action: NodeAction) {
    if (!menu) return;
    const { id } = menu.node;
    const ref = nodeIndex.get(id) ?? { node_id: id, kind: menu.node.kind, label: menu.node.label };
    switch (action) {
      case "paths-out":
        void runPath({ source_node_ids: [id], target: "tier0", direction: "outbound" }, `Paths to Tier Zero from ${ref.label}`);
        break;
      case "paths-in":
        void runPath({ target_node_ids: [id], direction: "inbound" }, `Who can reach ${ref.label}`);
        break;
      case "set-start":
        setPathForm((f) => ({ ...f, start: ref }));
        break;
      case "set-end":
        setPathForm((f) => ({ ...f, end: ref }));
        break;
      case "expand":
        // Seed a fresh depth-1 neighbourhood server-side (robust even when
        // leaving an analysis view); the walk continues from there on click.
        setAnalysis(null);
        setFilters({ ...DEFAULT_FILTERS, seed: ref, depth: 1 });
        setSelectedId(id);
        break;
      case "dossier":
        setSelectedId(id);
        break;
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
    const err = summaryQuery.error;
    if (err.status === 409 || err.status === 400) {
      const analyzing = live.state === "running" || live.state === "pending";
      return <NotReady caseId={caseId} analyzing={analyzing} />;
    }
    return (
      <div className="p-6">
        <ErrorState title="Failed to load graph" message={errorText(err)} />
      </div>
    );
  }

  if (summaryQuery.isLoading || !summaryQuery.data) {
    return (
      <div className="flex h-full min-h-0">
        <div className="w-[280px] shrink-0 border-r border-border bg-surface/60 p-4">
          <SkeletonRows rows={6} />
        </div>
        <div className="flex flex-1 items-center justify-center">
          <div className="w-full max-w-lg px-6">
            <Skeleton className="mx-auto mb-4 h-48 w-48 rounded-full" />
            <SkeletonRows rows={2} />
          </div>
        </div>
      </div>
    );
  }

  const slice = canvas.slice;
  const noEdges = Boolean(slice && slice.nodes.length > 0 && slice.edges.length === 0);
  // Offer connect-the-dots when the view has >=2 node kinds but 0 edges among them
  // (e.g. a User+GPO filter) — the honest edge set is empty but a connecting chain
  // through hidden intermediates exists. (Plain computation — after the early
  // returns above, so it must NOT be a hook.)
  const multiKind = new Set((slice?.nodes ?? []).map((n) => n.kind)).size >= 2;
  const canConnect = noEdges && multiKind && !analysis && !connector;
  const overridden =
    analysis !== null ||
    connector !== null ||
    explicitFilter(filters) ||
    filters.showStructure ||
    expandedIds.size > 0 ||
    walkSteps.length > 0;
  const showSidePanel = !focusMode;

  return (
    <div className="flex h-full min-h-0">
      {/* The ONE contextual left column (doc 10 §4.3): Hunts (library) + Filters
          (seed/depth/kind toggles + Path form) as tabs — no double rail, no
          nested catalog. Hidden in full-screen focus mode. */}
      {!focusMode ? (
        <SecondaryPanel
          moduleKey="graph"
          title="Capability Graph"
          defaultTabId="hunts"
          tabs={[
            {
              id: "hunts",
              label: "Hunts",
              icon: Zap,
              content: <HunterLibrary caseId={caseId} />,
            },
            {
              id: "filters",
              label: "Filters",
              icon: SlidersHorizontal,
              content: (
                <FilterRail
                  caseId={caseId}
                  summary={summaryQuery.data}
                  value={filters}
                  onChange={setFilters}
                  structuralCount={structuralCount}
                >
                  <PathForm
                    pathForm={pathForm}
                    pathRunning={pathRunning}
                    onSwap={() => setPathForm((f) => ({ start: f.end, end: f.start }))}
                    onClear={() => setPathForm({ start: null, end: null })}
                    onRun={() => {
                      if (pathForm.start && pathForm.end) {
                        void runPath(
                          { source_node_ids: [pathForm.start.node_id], target_node_ids: [pathForm.end.node_id], direction: "outbound" },
                          `${pathForm.start.label} → ${pathForm.end.label}`,
                        );
                      }
                    }}
                  />
                </FilterRail>
              ),
            },
          ]}
        />
      ) : null}

      {/* Results List: the current slice / active hunt as clickable rows. Selection
          is shared with the canvas (selectedId), so row ↔ node stay in sync and a
          row click opens the node's Inspector. The canvas itself is untouched. */}
      {showList && !focusMode && slice ? (
        <GraphList
          nodes={slice.nodes}
          truncated={slice.truncated}
          title={
            analysis?.title ??
            (connector ? "Connecting chains" : overridden ? "Current slice" : "Tier-0 neighbourhood")
          }
          selectedId={selectedId}
          resolvedTheme={resolvedTheme}
          onSelect={setSelectedId}
          onClose={() => setShowList(false)}
        />
      ) : null}

      <div className="relative min-w-0 flex-1 bg-background">
        {/* status / honesty overlay */}
        {slice ? (
          <div className="pointer-events-none absolute left-3 top-3 z-10 max-w-[min(90%,32rem)] rounded-md border border-border bg-surface-overlay/95 px-3 py-1.5 text-caption shadow-overlay backdrop-blur">
            {analysis?.kind === "set" ? (
              <>
                <span className="font-mono tabular-nums text-foreground">{analysis.slice.returned} / {analysis.slice.total_matched}</span>
                <span className="ml-1 text-muted-foreground">in set · {analysis.slice.edges.length} edges</span>
                {analysis.slice.truncated ? <span className="ml-2 text-degraded">— capped, refine</span> : null}
              </>
            ) : analysis?.kind === "path" ? (
              <span className="text-muted-foreground">
                attack paths · <span className="font-mono tabular-nums text-foreground">{slice.nodes.length}</span> nodes
              </span>
            ) : connector ? (
              <span className="text-muted-foreground">
                connecting chains ·{" "}
                <span className="font-mono tabular-nums text-accent">{connector.control_count}</span> control ·{" "}
                <span className="font-mono tabular-nums text-foreground">{connector.scope_count}</span> scope
                {connector.via_node_ids.length > 0 ? (
                  <span className="ml-1 text-degraded">
                    · +{connector.via_node_ids.length} intermediate node
                    {connector.via_node_ids.length === 1 ? "" : "s"} shown to connect
                  </span>
                ) : null}
              </span>
            ) : (
              <>
                <span className="font-mono tabular-nums text-foreground">{slice.nodes.length}</span>
                <span className="ml-1 text-muted-foreground">
                  nodes · {slice.edges.length} relationships
                  {expandedIds.size > 0 ? " · walking" : ""}
                </span>
                {slice.truncated ? <span className="ml-2 text-degraded">— capped at {SLICE_LIMIT}, refine</span> : null}
                {!overridden ? <span className="ml-2 text-muted-foreground">Tier-0 start · click a node to expand</span> : null}
              </>
            )}
            {walkNote ? <span className="ml-2 text-degraded">— {walkNote}</span> : null}
            {connector?.note ? <span className="ml-2 text-degraded">— {connector.note}</span> : null}
            {showAllLabels && !showAllGate.allowed ? (
              <span className="ml-2 text-degraded">— {showAllGate.reason}</span>
            ) : null}
          </div>
        ) : null}

        {/* Connect-the-dots prompt: >=2 kinds, 0 edges → offer the connecting path
            (honesty: intermediates are ADDED to connect, not filter matches). */}
        {canConnect ? (
          <div className="absolute left-1/2 top-16 z-10 w-[min(90%,30rem)] -translate-x-1/2 rounded-md border border-accent/30 bg-surface-overlay/95 p-3 text-caption shadow-overlay backdrop-blur">
            <p className="mb-2 leading-snug text-muted-foreground">
              These entities don&apos;t link directly. Show the connecting path through
              the hidden intermediate objects that relate them? The intermediates are
              <span className="text-foreground"> added to connect</span> — they are not
              filter matches.
            </p>
            <Button size="sm" className="h-7 w-full text-caption" disabled={connectorRunning} onClick={() => void runConnector()}>
              {connectorRunning ? <Loader2 className="size-3.5 animate-spin" /> : <Spline className="size-3.5" />}
              Show the connecting path
            </Button>
          </div>
        ) : null}

        {/* toolbar */}
        <div className="absolute right-3 top-3 z-10 flex items-center gap-2">
          {baseFetching || pathRunning || runningQueryId !== null ? (
            <span className="pointer-events-none flex items-center gap-1.5 rounded-md border border-border bg-surface-overlay/95 px-2 py-1 text-caption text-muted-foreground shadow-overlay backdrop-blur">
              <Loader2 className="size-3.5 animate-spin" /> working…
            </span>
          ) : null}
          {walkSteps.length > 0 ? (
            <ToolToggle title="Walk back (undo last expansion)" onClick={walkBack}>
              <Undo2 className="size-4" />
            </ToolToggle>
          ) : null}
          <ToolToggle title="Fit graph to view" onClick={() => setFitSignal((s) => s + 1)}>
            <Frame className="size-4" />
          </ToolToggle>
          <ToolToggle
            title={showAllLabels ? "Show labels on focus only" : "Show all relationship labels"}
            active={showAllLabels}
            onClick={() => setShowAllLabels((v) => !v)}
          >
            <Tags className="size-4" />
          </ToolToggle>
          {!focusMode ? (
            <ToolToggle
              title={showList ? "Hide list view" : "Show list of entities in this view"}
              active={showList}
              onClick={() => setShowList((v) => !v)}
            >
              <List className="size-4" />
            </ToolToggle>
          ) : null}
          <ToolToggle
            title={focusMode ? "Exit full screen" : "Full screen"}
            active={focusMode}
            onClick={() => setFocusMode((v) => !v)}
          >
            {focusMode ? <Minimize2 className="size-4" /> : <Maximize2 className="size-4" />}
          </ToolToggle>
          {overridden ? (
            <Button size="sm" variant="secondary" onClick={resetView}>
              <RotateCcw className="size-3.5" /> Reset
            </Button>
          ) : null}
        </div>

        {analysisError ? (
          <div className="absolute left-1/2 top-3 z-10 -translate-x-1/2 rounded-md border border-unavailable/40 bg-unavailable/10 px-3 py-1.5 text-caption text-unavailable">
            {analysisError}
          </div>
        ) : null}

        {baseError && !analysis ? (
          <div className="absolute inset-0 grid place-items-center p-6">
            <ErrorState title="Slice failed" message={errorText(baseError)} />
          </div>
        ) : slice && slice.nodes.length === 0 ? (
          <div className="absolute inset-0 grid place-items-center p-6">
            <EmptyState
              icon={analysis ? CheckCircle2 : undefined}
              title={analysis ? `0 found — nothing matched${analysis.title ? ` for "${analysis.title}"` : ""}` : "No nodes match"}
              hint={
                analysis
                  ? "A clean result — this hunt found no matching entities in this data."
                  : "No nodes match the current filters/seed. Reset the view or widen the depth."
              }
            />
          </div>
        ) : slice ? (
          <>
            <SigmaCanvas
              slice={slice}
              variant={canvas.variant}
              isolate={isolate}
              selectedId={selectedId}
              showAllEdgeLabels={effectiveShowAll}
              expandMode={expandMode}
              fitSignal={fitSignal}
              viaNodeIds={canvas.via}
              resolvedTheme={resolvedTheme}
              onSelectNode={setSelectedId}
              onExpandNode={(id) => void expandNode(id)}
              onNodeContextMenu={(id, x, y) => {
                const ref = nodeIndex.get(id);
                setMenu({ node: { id, label: ref?.label ?? id, kind: ref?.kind ?? "Base" }, x, y });
              }}
            />
            <Legend nodes={slice.nodes} edges={slice.edges} />
          </>
        ) : (
          <div className="absolute inset-0 grid place-items-center text-body text-muted-foreground">
            <span className="flex items-center gap-2">
              <Loader2 className="size-4 animate-spin" /> loading…
            </span>
          </div>
        )}
      </div>

      {/* Right panel: node inspector takes priority; else connector, else paths. */}
      {showSidePanel && selectedId ? (
        <Inspector caseId={caseId} nodeId={selectedId} onClose={() => setSelectedId(null)} />
      ) : showSidePanel && connector ? (
        <ConnectorPanel result={connector} onClose={resetView} />
      ) : showSidePanel && analysis?.kind === "path" ? (
        <PathResultPanel
          title={analysis.title}
          result={analysis.result}
          gaps={analysis.gaps}
          isolatedIndex={isolatedIndex}
          onIsolate={setIsolatedIndex}
          onClose={resetView}
        />
      ) : null}

      {menu ? (
        <NodeContextMenu
          node={menu.node}
          x={menu.x}
          y={menu.y}
          onAction={onMenuAction}
          onClose={() => setMenu(null)}
        />
      ) : null}
    </div>
  );
}
