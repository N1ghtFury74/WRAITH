import { ChevronDown, ChevronRight, Loader2, Route, Search, Zap } from "lucide-react";
import { useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import type { PrebuiltQuery } from "@/lib/api";
import { groupQueries, type QueryOutcome } from "@/lib/hunts/catalog";
import { CATEGORY_INTENT, HUNT_NOTES } from "@/lib/hunts/explanations";
import { cn } from "@/lib/utils";

/** Structured plain-English note shown when a hunt is expanded (operate-from-UI, no docs). */
function HuntDetail({ queryId }: { queryId: string }) {
  const note = HUNT_NOTES[queryId];
  if (!note) return null;
  return (
    <div className="mt-1.5 space-y-1 rounded border border-border/60 bg-surface-raised/40 p-2 text-micro leading-snug">
      <p>
        <span className="font-semibold text-foreground">Finds: </span>
        <span className="text-muted-foreground">{note.finds}</span>
      </p>
      <p>
        <span className="font-semibold text-foreground">Why it matters: </span>
        <span className="text-muted-foreground">{note.why}</span>
      </p>
      <p>
        <span className="font-semibold text-foreground">How to read: </span>
        <span className="text-muted-foreground">{note.read}</span>
      </p>
      <p>
        <span className="font-semibold text-degraded">Caveat: </span>
        <span className="text-muted-foreground">{note.caveat}</span>
      </p>
    </div>
  );
}

function QueryItem({
  q,
  active,
  running,
  outcome,
  onRun,
}: {
  q: PrebuiltQuery;
  active: boolean;
  running: boolean;
  outcome: QueryOutcome | null;
  onRun: () => void;
}) {
  const [open, setOpen] = useState(false);
  const disabled = !q.supported;
  const showOutcome = active && !running && outcome !== null;
  const hasNote = Boolean(HUNT_NOTES[q.id]);
  return (
    <div
      className={cn(
        "rounded-md border transition-colors duration-150",
        disabled
          ? "border-border"
          : active
            ? "border-accent/50 bg-accent/10"
            : "border-border hover:bg-surface-raised",
      )}
    >
      <div className="flex items-start gap-1">
        <button
          onClick={onRun}
          disabled={disabled || running}
          title={disabled ? (q.reason ?? "Out of scope for v1") : `Run: ${q.label}`}
          className={cn(
            "flex min-w-0 flex-1 items-start gap-2 px-2 py-1.5 text-left text-caption",
            disabled ? "cursor-not-allowed text-muted-foreground/60" : "text-muted-foreground",
          )}
        >
          {running ? (
            <Loader2 className="mt-0.5 size-3.5 shrink-0 animate-spin text-accent" />
          ) : q.kind === "path" ? (
            <Route className="mt-0.5 size-3.5 shrink-0" />
          ) : (
            <Zap className="mt-0.5 size-3.5 shrink-0" />
          )}
          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-center gap-1">
              <span className={cn("font-medium leading-tight", !disabled && "text-foreground")}>
                {q.label}
              </span>
              {q.source_count !== null ? (
                <span className="font-mono text-micro tabular-nums text-muted-foreground">
                  ({q.source_count})
                </span>
              ) : null}
            </span>
            {/* Visible one-line description — operate-from-UI, no docs (research 08 §2.4). */}
            <span className="mt-0.5 line-clamp-2 block text-micro leading-snug text-muted-foreground">
              {q.description}
            </span>
            {q.data_confidence === "synthetic-only" ? (
              <Badge
                variant="degraded"
                className="mt-1"
                title="Synthetic-only: inferred edges, synthetic-tested but UNtested on real captures (Certipy parity pending). Treat any result as a lead to verify."
              >
                synthetic
              </Badge>
            ) : null}
            {showOutcome ? (
              outcome!.isZero ? (
                <span className="mt-1 block text-micro text-muted-foreground">0 · none found</span>
              ) : (
                <span className="mt-1 block font-mono text-micro tabular-nums text-accent">
                  {outcome!.count} found
                </span>
              )
            ) : null}
            {disabled && q.reason ? (
              <span className="mt-0.5 block text-micro leading-snug text-muted-foreground">
                {q.reason}
              </span>
            ) : null}
          </span>
        </button>
        {hasNote ? (
          <button
            onClick={() => setOpen((v) => !v)}
            title={open ? "Hide explanation" : "Show explanation"}
            className="mt-1 mr-1 shrink-0 rounded p-1 text-muted-foreground hover:text-foreground focus-visible:ring-1 focus-visible:ring-ring"
          >
            {open ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
          </button>
        ) : null}
      </div>
      {open ? (
        <div className="px-2 pb-2">
          <HuntDetail queryId={q.id} />
        </div>
      ) : null}
    </div>
  );
}

interface Props {
  queries: PrebuiltQuery[] | undefined;
  loading: boolean;
  error: boolean;
  /** The hunt currently rendered in the canvas (deep-linked via ?hunt=) — highlighted. */
  activeQueryId: string | null;
  /** The hunt whose run is in flight (optional; shows the inline spinner). */
  runningQueryId?: string | null;
  /** Outcome for the active hunt (optional; the calm found/0-found chip). */
  activeOutcome?: QueryOutcome | null;
  onRunQuery: (q: PrebuiltQuery) => void;
  /** Collapsed category names (persisted by the parent). */
  collapsed: Set<string>;
  onToggleCategory: (category: string) => void;
}

/**
 * The reusable Hunter Library list: a search box + fixed-order collapsible
 * categories, each with its intent line and the hunts under it (visible
 * one-line descriptions, synthetic/unsupported badges, live source counts, an
 * expandable plain-English note). Presentational — category collapse is owned by
 * the parent (so it can persist); the search term is local. Pure grouping lives
 * in `@/lib/hunts/catalog`.
 */
export function HuntList({
  queries,
  loading,
  error,
  activeQueryId,
  runningQueryId = null,
  activeOutcome = null,
  onRunQuery,
  collapsed,
  onToggleCategory,
}: Props) {
  const [filter, setFilter] = useState("");
  const term = filter.trim().toLowerCase();
  const searching = term.length > 0;

  const groups = useMemo(() => groupQueries(queries, term), [queries, term]);

  return (
    <div>
      {/* Hunt search box */}
      <div className="relative mb-2">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="search hunts…"
          className="h-8 pl-8 text-caption"
          autoComplete="off"
        />
      </div>

      {loading ? (
        <div className="flex items-center gap-2 py-2 text-caption text-muted-foreground">
          <Loader2 className="size-3.5 animate-spin" /> loading hunts…
        </div>
      ) : error ? (
        <p className="text-caption text-unavailable">Could not load the query catalog.</p>
      ) : groups.length === 0 ? (
        <p className="px-1 py-2 text-micro text-muted-foreground">
          {searching ? `No hunts match “${filter.trim()}”.` : "No hunts available."}
        </p>
      ) : (
        <div className="space-y-2">
          {groups.map(([category, items]) => {
            // When searching, force matching categories open regardless of the
            // persisted collapse state (so results are never hidden).
            const open = searching || !collapsed.has(category);
            const intent = CATEGORY_INTENT[category];
            return (
              <div key={category}>
                <button
                  onClick={() => onToggleCategory(category)}
                  className="flex w-full items-center gap-1.5 rounded px-1 py-1 text-micro font-semibold uppercase tracking-[0.06em] text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-1 focus-visible:ring-ring"
                >
                  {open ? <ChevronDown className="size-3" /> : <ChevronRight className="size-3" />}
                  <span className="flex-1 text-left">{category}</span>
                  <span className="font-mono tabular-nums text-muted-foreground">{items.length}</span>
                </button>
                {open ? (
                  <div className="mt-1 space-y-1.5">
                    {intent ? (
                      <p className="px-1 text-micro leading-snug text-muted-foreground/80">
                        {intent}
                      </p>
                    ) : null}
                    {items.map((q) => (
                      <QueryItem
                        key={q.id}
                        q={q}
                        active={q.id === activeQueryId}
                        running={q.id === runningQueryId}
                        outcome={q.id === activeQueryId ? activeOutcome : null}
                        onRun={() => onRunQuery(q)}
                      />
                    ))}
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
