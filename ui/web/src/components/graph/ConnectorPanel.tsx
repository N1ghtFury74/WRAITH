import { ArrowDown, ShieldAlert, Spline, X } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/states";
import type { ConnectorPath, ConnectorResult } from "@/lib/api";
import { cn } from "@/lib/utils";

/** Friendly text for a connector counted-gap code (surfaced plainly, never silent). */
const GAP_TEXT: Record<string, string> = {
  rsop_not_resolvable:
    "GPO application is potential only — RSoP (security filtering / WMI / inheritance) cannot be resolved offline.",
  structural_only_suppressed:
    "Pure containment / co-location chains were suppressed (structure, not an attack relationship).",
  representatives_capped:
    "The retained set was large — a representative subset was used to bound the search.",
  hop_confidence_unknown: "Some hops carried no confidence value and were treated conservatively.",
  no_connection: "No connecting chain was found.",
  empty_node_set: "No valid nodes were supplied to connect.",
};

function gapText(code: string, count: number): string {
  return GAP_TEXT[code] ?? `${code}: ${count}`;
}

/** Default scope-lane caveat shown if the backend omitted one — a scope chain must
 *  NEVER render without its honesty note (tester flagged over-claim risk). */
const SCOPE_RSOP_CAVEAT =
  "Scope only — GPO application here is potential; RSoP (security filtering / WMI / link enforcement / inheritance) cannot be resolved offline.";

function laneBadge(lane: "control" | "scope") {
  return lane === "control" ? (
    <Badge variant="accent">control · capability</Badge>
  ) : (
    <Badge variant="degraded">scope · potential</Badge>
  );
}

function ChainRow({ p }: { p: ConnectorPath }) {
  const start = p.nodes[0]?.label ?? p.source_node_id;
  const end = p.nodes[p.nodes.length - 1]?.label ?? p.target_node_id;
  return (
    <li className="px-3 py-2">
      <div className="flex items-center justify-between gap-2">
        <span className="min-w-0 flex-1 truncate font-mono text-caption text-foreground" title={`${start} → ${end}`}>
          {start} → {end}
        </span>
        {laneBadge(p.lane)}
      </div>
      <div className="mt-1 flex items-center gap-2 text-micro text-muted-foreground">
        <span>{p.length} hops</span>
        <span
          className={cn(
            "font-mono",
            p.confidence === "confirmed" ? "text-foreground" : "text-degraded",
          )}
        >
          {p.confidence}
        </span>
      </div>
      <ol className="mt-2 space-y-1">
        {p.edges.map((seg, j) => (
          <li key={`${seg.source}-${seg.target}-${j}`} className="text-micro leading-tight">
            <span className="font-mono text-foreground">{p.nodes[j]?.label ?? seg.source}</span>
            <span className="mx-1 inline-flex items-center gap-0.5 text-accent">
              <ArrowDown className="size-3 rotate-[-90deg]" />
              {seg.kind}
            </span>
            <span className="font-mono text-foreground">{p.nodes[j + 1]?.label ?? seg.target}</span>
          </li>
        ))}
      </ol>
      {p.caveat || p.lane === "scope" ? (
        <p className="mt-1.5 flex items-start gap-1.5 rounded border border-degraded/30 bg-degraded/10 px-1.5 py-1 text-micro leading-snug text-degraded">
          <ShieldAlert className="mt-0.5 size-3 shrink-0" />
          <span>
            <span className="font-semibold">RSoP caveat: </span>
            {p.caveat ?? SCOPE_RSOP_CAVEAT}
          </span>
        </p>
      ) : null}
    </li>
  );
}

interface Props {
  result: ConnectorResult;
  onClose: () => void;
}

/**
 * Right-hand connect-the-dots result: two lanes (control chains ranked above scope),
 * each hop labelled with confidence, plus the honest "+N intermediate nodes" count,
 * the feature-level caveats (DENY-ACE over-statement; RSoP for scope), and every
 * counted gap. "No connection" is stated explicitly, never a blank.
 */
export function ConnectorPanel({ result, onClose }: Props) {
  const gapEntries = Object.entries(result.counted_gaps);
  const hasPaths = result.paths.length > 0;

  return (
    <aside className="flex w-96 shrink-0 flex-col overflow-y-auto border-l border-border bg-surface">
      <header className="flex items-center justify-between gap-2 border-b border-border p-3">
        <div className="flex min-w-0 items-center gap-2">
          <Spline className="size-4 shrink-0 text-accent" />
          <span className="truncate text-body font-semibold">Connecting paths</span>
        </div>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground" title="Close">
          <X className="size-4" />
        </button>
      </header>

      <div className="space-y-1.5 border-b border-border p-3 text-caption">
        <p className="text-muted-foreground">
          <span className="font-mono tabular-nums text-accent">{result.control_count}</span> control ·{" "}
          <span className="font-mono tabular-nums text-foreground">{result.scope_count}</span> scope
          {result.truncated ? <span className="ml-1 text-degraded">— more exist, capped</span> : null}
        </p>
        {result.via_node_ids.length > 0 ? (
          <p className="text-degraded">
            +{result.via_node_ids.length} intermediate node
            {result.via_node_ids.length === 1 ? "" : "s"} shown to connect (added, not filter matches)
          </p>
        ) : null}
        {gapEntries.map(([code, count]) => (
          <p key={code} className="text-degraded">
            {gapText(code, count)}
          </p>
        ))}
      </div>

      {!hasPaths ? (
        <div className="p-3">
          <EmptyState
            icon={Spline}
            title="No connection found"
            hint={result.note ?? "No attack-relevant or scope chain connects the selected entities."}
          />
        </div>
      ) : (
        <ul className="divide-y divide-border/60">
          {result.paths.map((p, i) => (
            <ChainRow key={`${p.source_node_id}-${p.target_node_id}-${i}`} p={p} />
          ))}
        </ul>
      )}

      {result.caveats.length > 0 ? (
        <div className="mt-auto space-y-1 border-t border-border p-3 text-micro leading-snug text-muted-foreground">
          {result.caveats.map((c) => (
            <p key={c} className="flex items-start gap-1.5">
              <ShieldAlert className="mt-0.5 size-3 shrink-0 text-degraded" />
              {c}
            </p>
          ))}
        </div>
      ) : null}
    </aside>
  );
}
