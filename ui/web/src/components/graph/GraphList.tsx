import { Search, X } from "lucide-react";
import { useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import type { ResolvedTheme } from "@/hooks/useTheme";
import type { GraphNode } from "@/lib/api";
import { nodeColor } from "@/lib/graph/encoding";
import { filterSliceNodes, listSummary, orderSliceNodes } from "@/lib/graph/list";
import { cn } from "@/lib/utils";

interface Props {
  /** The nodes of the slice the canvas is currently rendering (base, filter, or hunt). */
  nodes: GraphNode[];
  /** True when the slice was server-capped — the list is a partial view (stay honest). */
  truncated: boolean;
  /** A short heading for the current view (e.g. the active hunt's label). */
  title: string;
  /** The node id selected in the graph (shared with the canvas). */
  selectedId: string | null;
  resolvedTheme: ResolvedTheme;
  /** Select/focus a node — same handler the canvas uses, so row ↔ node stay in sync. */
  onSelect: (id: string) => void;
  /** Hide the list column. */
  onClose: () => void;
}

/**
 * The List view that mirrors the Capability Graph canvas (owner ask): the current
 * slice's — or the active Hunter result's — entities as clickable rows. Selection
 * is SHARED with the canvas (the same `selectedId`), so clicking a row focuses the
 * node in the graph and opens its Inspector, and selecting a node in the graph
 * highlights its row. It renders exactly what the canvas renders — same ids, same
 * labels, same Tier-0 marking — so the two never disagree. The canvas is untouched.
 */
export function GraphList({ nodes, truncated, title, selectedId, resolvedTheme, onSelect, onClose }: Props) {
  const [filter, setFilter] = useState("");
  const ordered = useMemo(() => orderSliceNodes(nodes), [nodes]);
  const filtered = useMemo(() => filterSliceNodes(ordered, filter), [ordered, filter]);
  const summary = useMemo(() => listSummary(nodes, truncated), [nodes, truncated]);

  return (
    <div className="flex h-full w-[280px] shrink-0 flex-col border-r border-border bg-surface/60">
      {/* Header: title + honest counts + close */}
      <div className="flex items-start justify-between gap-2 border-b border-border px-3 py-2.5">
        <div className="min-w-0">
          <p className="eyebrow">List · {title}</p>
          <p className="mt-0.5 text-caption text-muted-foreground">
            <span className="font-mono tabular-nums text-foreground">{summary.total}</span> entit
            {summary.total === 1 ? "y" : "ies"}
            {summary.tier0 > 0 ? (
              <>
                {" · "}
                <span className="font-mono tabular-nums text-tier0">{summary.tier0}</span> Tier-0
              </>
            ) : null}
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          title="Hide list"
          aria-label="Hide list"
          className="shrink-0 rounded-md p-1 text-muted-foreground transition-colors hover:bg-surface-raised hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <X className="size-4" />
        </button>
      </div>

      {/* Filter */}
      {nodes.length > 8 ? (
        <div className="border-b border-border p-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="filter entities…"
              className="h-8 pl-8 text-body-sm"
              autoComplete="off"
            />
          </div>
        </div>
      ) : null}

      {truncated ? (
        <p className="border-b border-border bg-degraded/5 px-3 py-1.5 text-micro leading-snug text-degraded">
          Capped view — refine the filters to narrow the set. The graph and this list show the same
          entities.
        </p>
      ) : null}

      {/* Rows */}
      <ul className="min-h-0 flex-1 overflow-y-auto py-1" aria-label="Graph entities">
        {filtered.length === 0 ? (
          <li className="px-3 py-6 text-center text-caption text-muted-foreground">
            {nodes.length === 0 ? "No entities in this view." : `No entities match “${filter.trim()}”.`}
          </li>
        ) : (
          filtered.map((n) => {
            const active = n.node_id === selectedId;
            return (
              <li key={n.node_id}>
                <button
                  type="button"
                  onClick={() => onSelect(n.node_id)}
                  aria-current={active}
                  title={n.label}
                  className={cn(
                    "flex w-full items-center gap-2 px-3 py-1.5 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring",
                    active ? "bg-accent/10" : "hover:bg-surface-raised",
                  )}
                >
                  <span
                    className="size-2.5 shrink-0 rounded-full"
                    style={{ backgroundColor: nodeColor(n, resolvedTheme) }}
                  />
                  <span className="min-w-0 flex-1">
                    <span
                      className={cn(
                        "block truncate text-body-sm leading-tight",
                        active ? "font-medium text-accent" : "text-foreground",
                      )}
                    >
                      {n.label}
                    </span>
                    <span className="block truncate text-micro text-muted-foreground">{n.kind}</span>
                  </span>
                  {n.highvalue ? <Badge variant="tier0">Tier-0</Badge> : null}
                </button>
              </li>
            );
          })
        )}
      </ul>
    </div>
  );
}
