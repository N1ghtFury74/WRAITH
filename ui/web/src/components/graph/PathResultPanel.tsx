import { ArrowDown, Route, Target, X } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/states";
import type { PathResult } from "@/lib/api";
import { pathSegments } from "@/lib/graph/paths";
import { cn } from "@/lib/utils";

/** Friendly text for a counted-gap code (design §7.5 — surfaced plainly). */
const GAP_TEXT: Record<string, string> = {
  empty_source_set: "No principals matched this query's source set in this data.",
  empty_target_set: "No target nodes for this query exist in this data.",
  no_tier0_target: "No Tier-0 target exists in this data.",
  domain_users_group_absent: "No Domain Users (-513) group was found in this data.",
  domain_users_empty_effective_membership:
    "The Domain Users group has no resolved effective members.",
};

function gapText(code: string, count: number): string {
  return GAP_TEXT[code] ?? `${code}: ${count}`;
}

interface Props {
  title: string;
  result: PathResult;
  gaps: Record<string, number>;
  isolatedIndex: number | null;
  onIsolate: (index: number | null) => void;
  onClose: () => void;
}

/** Right-hand attack-path result: honest truncation + clickable hop-by-hop list. */
export function PathResultPanel({ title, result, gaps, isolatedIndex, onIsolate, onClose }: Props) {
  const gapEntries = Object.entries(gaps);
  const hasPaths = result.paths.length > 0;

  return (
    <aside className="flex w-96 shrink-0 flex-col overflow-y-auto border-l border-border bg-surface">
      <header className="flex items-center justify-between gap-2 border-b border-border p-3">
        <div className="flex min-w-0 items-center gap-2">
          <Route className="size-4 shrink-0 text-accent" />
          <span className="truncate text-body font-semibold" title={title}>
            {title}
          </span>
        </div>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground" title="Close">
          <X className="size-4" />
        </button>
      </header>

      {/* Honest truncation / counts (design §7.5) */}
      <div className="space-y-1.5 border-b border-border p-3 text-caption">
        <p className="text-muted-foreground">
          <span className="font-mono tabular-nums text-foreground">{result.paths_found}</span> path
          {result.paths_found === 1 ? "" : "s"} found
          {result.truncated ? (
            <span className="text-degraded">
              {" "}
              — showing {result.paths.length} (shortest-first); raise max_paths for more
            </span>
          ) : null}
        </p>
        {result.over_budget_targets.length > 0 ? (
          <p className="text-degraded">
            {result.over_budget_targets.length} target
            {result.over_budget_targets.length === 1 ? "" : "s"} reachable beyond {result.max_hops}{" "}
            hops — raise max_hops
          </p>
        ) : null}
        {result.unreachable_targets.length > 0 && hasPaths ? (
          <p className="text-muted-foreground">
            {result.unreachable_targets.length} target
            {result.unreachable_targets.length === 1 ? "" : "s"} with no attack path found
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
            icon={Target}
            title="No attack path found"
            hint={
              gapEntries.length > 0
                ? gapText(gapEntries[0][0], gapEntries[0][1])
                : "No route exists to the target within the hop limit for this data."
            }
          />
        </div>
      ) : (
        <>
          {isolatedIndex !== null ? (
            <div className="border-b border-border p-2">
              <Button size="sm" variant="secondary" className="w-full text-caption" onClick={() => onIsolate(null)}>
                Show all {result.paths.length} paths
              </Button>
            </div>
          ) : null}
          <ul className="divide-y divide-border/60">
            {result.paths.map((p, i) => {
              const isolated = isolatedIndex === i;
              const segments = pathSegments(p);
              return (
                <li key={`${p.nodes[0]?.node_id ?? i}-${p.target_node_id}-${i}`}>
                  <button
                    onClick={() => onIsolate(isolated ? null : i)}
                    className={cn(
                      "w-full px-3 py-2 text-left transition-colors",
                      isolated ? "bg-accent/10" : "hover:bg-surface-raised/50",
                    )}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="min-w-0 flex-1 truncate font-mono text-caption text-foreground">
                        {p.nodes[0]?.label ?? "?"} → {p.target_label}
                      </span>
                      <Badge variant={isolated ? "accent" : "outline"}>{p.length} hops</Badge>
                    </div>
                    {isolated ? (
                      <ol className="mt-2 space-y-1">
                        {segments.map((seg, j) => (
                          <li key={j} className="text-micro leading-tight">
                            <span className="font-mono text-foreground">{seg.from}</span>
                            <span className="mx-1 inline-flex items-center gap-0.5 text-accent">
                              <ArrowDown className="size-3 rotate-[-90deg]" />
                              {seg.kind}
                            </span>
                            <span className="font-mono text-foreground">{seg.to}</span>
                          </li>
                        ))}
                      </ol>
                    ) : null}
                  </button>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </aside>
  );
}
