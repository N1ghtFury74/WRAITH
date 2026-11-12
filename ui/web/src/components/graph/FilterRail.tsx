import { useQuery } from "@tanstack/react-query";
import { ChevronDown, Crosshair, Search, X } from "lucide-react";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { useTheme } from "@/hooks/useTheme";
import { api, type CaseSummary, type NodeRef } from "@/lib/api";
import { kindColor } from "@/lib/graph/encoding";
import { cn } from "@/lib/utils";

export interface GraphFilters {
  /** empty set = all kinds */
  nodeKinds: Set<string>;
  edgeKinds: Set<string>;
  tier0Only: boolean;
  seed: NodeRef | null;
  depth: number;
  /** Show structural scaffolding (Containers/OUs/Base) — OFF by default (doc 19 P1.1). */
  showStructure: boolean;
}

export const DEFAULT_FILTERS: GraphFilters = {
  nodeKinds: new Set(),
  edgeKinds: new Set(),
  tier0Only: false,
  seed: null,
  depth: 2,
  showStructure: false,
};

/** Structural scaffolding kinds hidden by default (Contains-only noise, doc 19 P1.1). */
export const STRUCTURAL_KINDS = new Set(["Container", "Base", "OUContainer"]);

interface Props {
  caseId: string;
  summary: CaseSummary;
  value: GraphFilters;
  onChange: (next: GraphFilters) => void;
  /** Count of structural nodes hidden by default (drives the toggle's "+N"). */
  structuralCount: number;
  /** Rendered above the filter sections (the Analysis panel lives here). */
  children?: React.ReactNode;
}

function toggle(set: Set<string>, key: string): Set<string> {
  const next = new Set(set);
  if (next.has(key)) next.delete(key);
  else next.add(key);
  return next;
}

function KindToggle({
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
        "flex w-full items-center gap-2 rounded px-2 py-1 text-left text-caption transition-colors duration-150 focus-visible:ring-1 focus-visible:ring-ring",
        active ? "bg-accent/15 text-foreground" : "text-muted-foreground hover:bg-surface-raised",
      )}
    >
      {dot ? <span className="size-2 shrink-0 rounded-full" style={{ backgroundColor: dot }} /> : null}
      <span className="flex-1 truncate font-mono">{label}</span>
      <span className="font-mono text-micro tabular-nums text-muted-foreground">{count}</span>
    </button>
  );
}

/**
 * Filter controls (node/edge-kind toggles, Tier-0, structure, seed search) +
 * optional `children` (the Path form) rendered above. The outer column chrome
 * (width, border, scroll) is owned by the {@link SecondaryPanel} "Filters" tab
 * that hosts this — so this renders only the content (doc 10 §4.3).
 */
export function FilterRail({ caseId, summary, value, onChange, structuralCount, children }: Props) {
  const [q, setQ] = useState("");
  const { resolvedTheme } = useTheme();

  const searchQuery = useQuery({
    queryKey: ["search", caseId, q],
    queryFn: () => api.search(caseId, q, 12),
    enabled: q.trim().length >= 1,
  });

  const nodeKinds = Object.entries(summary.node_kind_counts).sort((a, b) => a[0].localeCompare(b[0]));
  const edgeKinds = Object.entries(summary.edge_kind_counts).sort((a, b) => a[0].localeCompare(b[0]));

  const allNodes = value.nodeKinds.size === 0;
  const allEdges = value.edgeKinds.size === 0;

  return (
    <div>
      {children ? <div className="mb-4">{children}</div> : null}

      {/* Seed search */}
      <section className="mb-4">
        <p className="eyebrow mb-1.5">Seed</p>
        {value.seed ? (
          <div className="mb-2 flex items-center gap-2 rounded border border-accent/30 bg-accent/10 px-2 py-1 text-caption">
            <Crosshair className="size-3.5 text-accent" />
            <span className="min-w-0 flex-1 truncate font-mono" title={value.seed.label}>
              {value.seed.label}
            </span>
            <button
              onClick={() => onChange({ ...value, seed: null })}
              className="text-muted-foreground hover:text-foreground"
              title="Clear seed (show whole graph)"
            >
              <X className="size-3.5" />
            </button>
          </div>
        ) : null}
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="name · SID · SPN · DN"
            className="h-8 pl-8 text-caption"
            autoComplete="off"
          />
        </div>
        {q.trim().length >= 1 && searchQuery.data ? (
          <ul className="mt-1 max-h-48 overflow-y-auto rounded border border-border bg-surface-raised">
            {searchQuery.data.hits.length === 0 ? (
              <li className="px-2 py-1.5 text-caption text-muted-foreground">No matches.</li>
            ) : (
              searchQuery.data.hits.map((h) => (
                <li key={h.node_id}>
                  <button
                    onClick={() => {
                      onChange({ ...value, seed: h });
                      setQ("");
                    }}
                    className="flex w-full items-center gap-2 px-2 py-1.5 text-left text-caption hover:bg-muted"
                  >
                    <span
                      className="size-2 shrink-0 rounded-full"
                      style={{ backgroundColor: kindColor(h.kind, resolvedTheme) }}
                    />
                    <span className="min-w-0 flex-1 truncate font-mono">{h.label}</span>
                    <span className="shrink-0 font-mono text-micro text-muted-foreground">{h.kind}</span>
                  </button>
                </li>
              ))
            )}
          </ul>
        ) : null}
        {value.seed ? (
          <div className="mt-2 flex items-center justify-between">
            <label htmlFor="depth" className="text-caption text-muted-foreground">
              Depth
            </label>
            <input
              id="depth"
              type="number"
              min={0}
              max={6}
              value={value.depth}
              onChange={(e) =>
                onChange({ ...value, depth: Math.max(0, Math.min(6, Number(e.target.value) || 0)) })
              }
              className="h-7 w-16 rounded border border-input bg-surface-raised px-2 text-caption"
            />
          </div>
        ) : null}
      </section>

      {/* Tier-0 */}
      <section className="mb-4">
        <button
          onClick={() => onChange({ ...value, tier0Only: !value.tier0Only })}
          className={cn(
            "flex w-full items-center gap-2 rounded px-2 py-1.5 text-caption font-medium transition-colors",
            value.tier0Only
              ? "bg-tier0/15 text-tier0"
              : "text-muted-foreground hover:bg-surface-raised",
          )}
        >
          <span className="size-2.5 rounded-full bg-tier0" />
          Tier-0 only
          {value.tier0Only ? <Badge variant="unavailable">on</Badge> : null}
        </button>
      </section>

      {/* Structure toggle (Containers/OUs hidden by default — doc 19 P1.1) */}
      {structuralCount > 0 ? (
        <section className="mb-4">
          <button
            onClick={() => onChange({ ...value, showStructure: !value.showStructure })}
            className={cn(
              "flex w-full items-center gap-2 rounded px-2 py-1.5 text-caption font-medium transition-colors duration-150 focus-visible:ring-1 focus-visible:ring-ring",
              value.showStructure ? "bg-accent/15 text-accent" : "text-muted-foreground hover:bg-surface-raised",
            )}
          >
            <span
              className={cn(
                "flex h-4 w-7 shrink-0 items-center rounded-full px-0.5 transition-colors",
                value.showStructure ? "justify-end bg-accent/60" : "justify-start bg-muted",
              )}
            >
              <span className="size-3 rounded-full bg-foreground" />
            </span>
            <span className="flex-1 text-left">Show structure (OUs/Containers)</span>
            <span className="font-mono text-micro tabular-nums text-muted-foreground">
              +{structuralCount}
            </span>
          </button>
        </section>
      ) : null}

      {/* Filters — collapsed by default so the rail stays minimal. Uncontrolled
          (<details> without `open`) so a re-render from search typing can't snap
          a manually-opened section shut; the "· N on" badge flags active filters. */}
      <details className="group mb-3">
        <summary className="flex cursor-pointer list-none items-center justify-between rounded px-1 py-1 text-muted-foreground hover:text-foreground">
          <span className="eyebrow">Node kinds{!allNodes ? ` · ${value.nodeKinds.size} on` : ""}</span>
          <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" />
        </summary>
        <div className="mt-1 space-y-0.5">
          {!allNodes ? (
            <button
              onClick={() => onChange({ ...value, nodeKinds: new Set() })}
              className="mb-1 block text-micro text-accent hover:underline"
            >
              clear node filter
            </button>
          ) : null}
          {nodeKinds.map(([kind, count]) => (
            <KindToggle
              key={kind}
              label={kind}
              count={count}
              dot={kindColor(kind, resolvedTheme)}
              active={allNodes || value.nodeKinds.has(kind)}
              onClick={() => onChange({ ...value, nodeKinds: toggle(value.nodeKinds, kind) })}
            />
          ))}
        </div>
      </details>

      <details className="group">
        <summary className="flex cursor-pointer list-none items-center justify-between rounded px-1 py-1 text-muted-foreground hover:text-foreground">
          <span className="eyebrow">Edge kinds{!allEdges ? ` · ${value.edgeKinds.size} on` : ""}</span>
          <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" />
        </summary>
        <div className="mt-1 space-y-0.5">
          {!allEdges ? (
            <button
              onClick={() => onChange({ ...value, edgeKinds: new Set() })}
              className="mb-1 block text-micro text-accent hover:underline"
            >
              clear edge filter
            </button>
          ) : null}
          {edgeKinds.map(([kind, count]) => (
            <KindToggle
              key={kind}
              label={kind}
              count={count}
              active={allEdges || value.edgeKinds.has(kind)}
              onClick={() => onChange({ ...value, edgeKinds: toggle(value.edgeKinds, kind) })}
            />
          ))}
        </div>
      </details>
    </div>
  );
}
