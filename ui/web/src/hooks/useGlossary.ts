import { useQuery } from "@tanstack/react-query";

import { api, type Glossary } from "@/lib/api";

/**
 * The static rights/attributes glossary (GET /glossary). Not case-scoped and
 * immutable, so it is fetched ONCE and cached across every dossier for the app's
 * lifetime (no refetch, no GC). Degrades gracefully: consumers render raw kinds +
 * a neutral caption when the data is absent (endpoint not live / loading).
 */
export function useGlossary() {
  return useQuery<Glossary>({
    queryKey: ["glossary"],
    queryFn: () => api.glossary(),
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
  });
}
