import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { HuntList } from "@/components/hunts/HuntList";
import { api, type PrebuiltQuery } from "@/lib/api";
import { readLs, writeLs } from "@/lib/storage";

const LS_COLLAPSED = "wraith.hunter.collapsed";

interface Props {
  caseId: string;
}

/**
 * The Hunter Library as it lives nested under the "Capability Graph" item in the
 * left module sidebar (owner's explicit ask: a toggle list, not a panel crowding
 * the canvas). Fetches the prebuilt-query catalog, renders the reusable
 * {@link HuntList}, and runs a hunt by deep-linking to the graph route:
 * `/case/:id/graph?hunt=<query_id>`. GraphPage reads that param and runs the hunt
 * in the canvas — no shared global store needed. Category collapse persists in
 * localStorage; the active hunt (from the URL) is highlighted.
 */
export function HunterLibrary({ caseId }: Props) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const activeQueryId = searchParams.get("hunt");

  const queriesQuery = useQuery<PrebuiltQuery[]>({
    queryKey: ["analysis-queries", caseId],
    queryFn: () => api.listQueries(caseId),
  });

  const [collapsed, setCollapsed] = useState<Set<string>>(
    () => new Set(readLs<string[]>(LS_COLLAPSED, [])),
  );
  useEffect(() => writeLs(LS_COLLAPSED, [...collapsed]), [collapsed]);

  function toggleCategory(category: string) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(category)) next.delete(category);
      else next.add(category);
      return next;
    });
  }

  function runHunt(q: PrebuiltQuery) {
    if (!q.supported) return;
    // Deep-linkable: the graph route owns the run; the param is the contract.
    navigate(`/case/${encodeURIComponent(caseId)}/graph?hunt=${encodeURIComponent(q.id)}`);
  }

  return (
    <HuntList
      queries={queriesQuery.data}
      loading={queriesQuery.isLoading}
      error={Boolean(queriesQuery.error)}
      activeQueryId={activeQueryId}
      onRunQuery={runHunt}
      collapsed={collapsed}
      onToggleCategory={toggleCategory}
    />
  );
}
