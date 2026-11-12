import { useQuery } from "@tanstack/react-query";

import { api, type CaseListItem } from "@/lib/api";

/** Shared query for the authoritative on-disk case list (GET /api/v1/cases). */
export function useCaseList() {
  return useQuery<CaseListItem[]>({
    queryKey: ["cases"],
    queryFn: () => api.listCases(),
  });
}
