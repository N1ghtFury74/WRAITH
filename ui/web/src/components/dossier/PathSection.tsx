import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Loader2, Route } from "lucide-react";

import { api, type PathRequest, type PathResult } from "@/lib/api";
import { pathSegments } from "@/lib/graph/paths";
import { errorText } from "@/lib/reasons";

interface Props {
  caseId: string;
  nodeId: string;
  direction: "outbound" | "inbound";
  /** Print mode renders statically (no spinner affordance text). */
  print?: boolean;
}

/**
 * Lazy attack-path panel for a dossier (sections 8/9). Outbound = shortest paths
 * to Tier-0 from this node; inbound = who can reach this node. Honest empty state
 * ("no path found") — never a silent blank.
 */
export function PathSection({ caseId, nodeId, direction, print }: Props) {
  const body: PathRequest =
    direction === "outbound"
      ? { source_node_ids: [nodeId], target: "tier0", direction: "outbound", max_hops: 8, max_paths: 25 }
      : { target_node_ids: [nodeId], direction: "inbound", max_hops: 8, max_paths: 25 };

  const { data, isLoading, error } = useQuery<PathResult>({
    queryKey: ["dossier-paths", caseId, nodeId, direction],
    queryFn: () => api.paths(caseId, body),
  });

  if (isLoading) {
    return (
      <p className="flex items-center gap-2 text-caption text-muted-foreground">
        {!print ? <Loader2 className="size-3.5 animate-spin" /> : null} computing paths…
      </p>
    );
  }
  if (error) {
    return <p className="text-caption text-unavailable">{errorText(error)}</p>;
  }
  if (!data || data.paths.length === 0) {
    return (
      <p className="text-caption text-muted-foreground">
        {direction === "outbound"
          ? "No attack path to Tier-0 found within the hop limit."
          : "No principal can reach this node within the hop limit."}
      </p>
    );
  }

  return (
    <div className="space-y-2">
      <p className="text-caption text-muted-foreground">
        <span className="font-mono tabular-nums text-foreground">{data.paths_found}</span> path
        {data.paths_found === 1 ? "" : "s"} found
        {data.truncated ? ` — showing ${data.paths.length} (shortest-first)` : ""}
      </p>
      <ol className="space-y-2">
        {data.paths.map((p, i) => (
          <li key={`${p.nodes[0]?.node_id ?? i}-${p.target_node_id}-${i}`} className="text-micro">
            <div className="mb-0.5 flex items-center gap-1.5 text-muted-foreground">
              <Route className="size-3 text-accent" />
              <span className="font-mono text-foreground">{p.nodes[0]?.label ?? "?"}</span>
              <ArrowRight className="size-3" />
              <span className="font-mono text-foreground">{p.target_label}</span>
              <span className="text-muted-foreground">· {p.length} hops</span>
            </div>
            <div className="flex flex-wrap items-center gap-1 pl-4">
              {pathSegments(p).map((seg, j) => (
                <span key={j} className="text-muted-foreground">
                  {j > 0 ? <span className="mx-0.5">·</span> : null}
                  <span className="text-accent">{seg.kind}</span>
                  <ArrowRight className="mx-0.5 inline size-2.5" />
                  <span className="font-mono text-foreground">{seg.to}</span>
                </span>
              ))}
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
