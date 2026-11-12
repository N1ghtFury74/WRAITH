import { create } from "zustand";
import { persist } from "zustand/middleware";

import type { RunState } from "@/lib/api";

/**
 * Client-side registry of cases the operator has created or attached in THIS
 * browser.
 *
 * Why client-side: the WRAITH API (`wraith/api/ingest.py`) exposes case
 * *creation* (`POST /cases`) and per-case reads, but no endpoint that lists every
 * case workspace on disk. So the authoritative selector of "which case" is the
 * `case_id` in the route; this store is just the convenience list + last-known
 * run outcome that powers the top-bar selector and the Graph/Dossiers READY
 * badges. A case created from the CLI can be attached by id (validated against
 * `GET /catalog`). Documented as a deliberate FE-1 decision (see README).
 */
export interface KnownCase {
  caseId: string;
  operator: string | null;
  createdAt: string | null;
  /** Last run state observed for this case (drives READY indicators). */
  lastRunState: RunState | null;
  lastRunId: string | null;
}

interface CasesState {
  cases: KnownCase[];
  addCase: (c: Omit<KnownCase, "lastRunState" | "lastRunId">) => void;
  removeCase: (caseId: string) => void;
  setRunState: (caseId: string, runId: string | null, state: RunState | null) => void;
  get: (caseId: string) => KnownCase | undefined;
}

export const useCasesStore = create<CasesState>()(
  persist(
    (set, getState) => ({
      cases: [],
      addCase: (c) =>
        set((s) => {
          if (s.cases.some((x) => x.caseId === c.caseId)) return s;
          return {
            cases: [...s.cases, { ...c, lastRunState: null, lastRunId: null }].sort((a, b) =>
              a.caseId.localeCompare(b.caseId),
            ),
          };
        }),
      removeCase: (caseId) => set((s) => ({ cases: s.cases.filter((x) => x.caseId !== caseId) })),
      setRunState: (caseId, runId, state) =>
        set((s) => ({
          cases: s.cases.map((x) =>
            x.caseId === caseId ? { ...x, lastRunId: runId, lastRunState: state } : x,
          ),
        })),
      get: (caseId) => getState().cases.find((x) => x.caseId === caseId),
    }),
    { name: "wraith.cases.v1" },
  ),
);
