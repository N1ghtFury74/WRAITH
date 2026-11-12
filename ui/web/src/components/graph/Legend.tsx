import { useTheme } from "@/hooks/useTheme";
import type { GraphEdge, GraphNode } from "@/lib/api";
import { edgeLegendForSlice, legendForSlice } from "@/lib/graph/encoding";

/**
 * Floating legend of the node kinds + AD CS relationship groups actually present
 * in the current slice. The AD CS section is shown only when certificate-services
 * edges are drawn: a "topology" row (confirmed PKI shape) and an "ESC (inferred)"
 * row flagged `synthetic` so a composed, synthetic-tested hop never reads as a
 * confirmed base edge (the certificate surface is synthetic-only in v1).
 */
export function Legend({ nodes, edges = [] }: { nodes: GraphNode[]; edges?: GraphEdge[] }) {
  const { resolvedTheme } = useTheme();
  const entries = legendForSlice(nodes, resolvedTheme);
  const edgeEntries = edgeLegendForSlice(edges, resolvedTheme);
  if (entries.length === 0 && edgeEntries.length === 0) return null;
  return (
    <div className="pointer-events-none absolute bottom-3 left-3 rounded-md border border-border bg-surface-overlay/95 p-2 shadow-overlay backdrop-blur">
      {entries.length > 0 ? (
        <>
          <p className="eyebrow mb-1">Legend</p>
          <ul className="space-y-0.5">
            {entries.map((e) => (
              <li key={e.kind} className="flex items-center gap-2 text-caption text-muted-foreground">
                <span className="size-2.5 rounded-full" style={{ backgroundColor: e.color }} />
                {e.kind}
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {edgeEntries.length > 0 ? (
        <div className="mt-2 border-t border-border/60 pt-1.5">
          <p className="eyebrow mb-1">AD CS relationships</p>
          <ul className="space-y-0.5">
            {edgeEntries.map((e) => (
              <li key={e.label} className="flex items-center gap-2 text-caption text-muted-foreground">
                {/* A short line swatch (relationships, not node dots). */}
                <span className="h-0.5 w-3 shrink-0 rounded-full" style={{ backgroundColor: e.color }} />
                <span>{e.label}</span>
                {e.inferred ? (
                  <span className="rounded-full border border-degraded/40 bg-degraded/10 px-1 text-micro font-medium leading-tight text-degraded">
                    synthetic
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
