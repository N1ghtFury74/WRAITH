import { create } from "zustand";

import type { RunState } from "@/lib/api";

/** Live analyze-run snapshot for one case, shared shell-wide (status bar, badges). */
export interface LiveRun {
  runId: string | null;
  state: RunState | null;
  percent: number;
  currentPass: string | null;
  error: string | null;
  coverageCounts: Record<string, number>;
  skipCounts: Record<string, number>;
  /** Whether a WS stream is currently connected for this case. */
  connected: boolean;
}

const EMPTY: LiveRun = {
  runId: null,
  state: null,
  percent: 0,
  currentPass: null,
  error: null,
  coverageCounts: {},
  skipCounts: {},
  connected: false,
};

interface RunStoreState {
  runs: Record<string, LiveRun>;
  update: (caseId: string, patch: Partial<LiveRun>) => void;
  reset: (caseId: string) => void;
}

export const useRunStore = create<RunStoreState>((set) => ({
  runs: {},
  update: (caseId, patch) =>
    set((s) => ({
      runs: { ...s.runs, [caseId]: { ...(s.runs[caseId] ?? EMPTY), ...patch } },
    })),
  reset: (caseId) => set((s) => ({ runs: { ...s.runs, [caseId]: { ...EMPTY } } })),
}));

/** Read a case's live run (or the empty default). Stable reference-safe selector. */
export function useLiveRun(caseId: string | undefined): LiveRun {
  return useRunStore((s) => (caseId ? (s.runs[caseId] ?? EMPTY) : EMPTY));
}

export const EMPTY_RUN = EMPTY;
