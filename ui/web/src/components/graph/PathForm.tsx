import { ArrowRight, ArrowRightLeft, Loader2, Route } from "lucide-react";

import { Button } from "@/components/ui/button";
import type { NodeRef } from "@/lib/api";

export interface PathFormState {
  start: NodeRef | null;
  end: NodeRef | null;
}

interface Props {
  pathForm: PathFormState;
  pathRunning: boolean;
  onSwap: () => void;
  onClear: () => void;
  onRun: () => void;
}

/**
 * Node-to-node pathing form — an interactive canvas tool (not a saved hunt), so
 * it stays in the graph's own rail while the hunt LIBRARY lives in the sidebar.
 * Right-click a node sets start/end; this renders the pending from/to pair with
 * find / swap / clear. When no endpoints are set it shows the discovery hint.
 */
export function PathForm({ pathForm, pathRunning, onSwap, onClear, onRun }: Props) {
  const hasForm = Boolean(pathForm.start || pathForm.end);

  return (
    <section className="border-b border-border pb-4">
      <p className="eyebrow mb-2 flex items-center gap-1.5">
        <Route className="size-3.5" />
        Path between nodes
      </p>
      {hasForm ? (
        <div className="space-y-1.5 rounded-md border border-accent/30 bg-accent/5 p-2">
          <div className="flex items-center gap-1.5 text-caption">
            <span className="w-8 shrink-0 text-muted-foreground">from</span>
            <span className="min-w-0 flex-1 truncate font-mono" title={pathForm.start?.label}>
              {pathForm.start?.label ?? (
                <span className="text-muted-foreground">set a start node</span>
              )}
            </span>
          </div>
          <div className="flex items-center gap-1.5 text-caption">
            <span className="w-8 shrink-0 text-muted-foreground">to</span>
            <span className="min-w-0 flex-1 truncate font-mono" title={pathForm.end?.label}>
              {pathForm.end?.label ?? <span className="text-muted-foreground">set an end node</span>}
            </span>
          </div>
          <div className="flex gap-1.5 pt-1">
            <Button
              size="sm"
              className="h-7 flex-1 text-caption"
              disabled={!pathForm.start || !pathForm.end || pathRunning}
              onClick={onRun}
            >
              {pathRunning ? (
                <Loader2 className="size-3.5 animate-spin" />
              ) : (
                <ArrowRight className="size-3.5" />
              )}
              Find path
            </Button>
            <Button
              size="icon"
              variant="secondary"
              className="h-7 w-7"
              title="Swap start / end"
              disabled={pathRunning}
              onClick={onSwap}
            >
              <ArrowRightLeft className="size-3.5" />
            </Button>
            <Button size="sm" variant="ghost" className="h-7 text-caption" onClick={onClear}>
              clear
            </Button>
          </div>
        </div>
      ) : (
        <p className="text-micro leading-snug text-muted-foreground">
          Right-click any node for path actions, or pick the Hunter Library in the sidebar to run a
          hunt.
        </p>
      )}
    </section>
  );
}
