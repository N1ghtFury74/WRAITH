import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";

import { api, ApiError, progressWsUrl, type AnalyzeRequest, type ProgressEvent } from "@/lib/api";
import { useCasesStore } from "@/store/cases";
import { useRunStore } from "@/store/run";

const TERMINAL = new Set(["done", "failed"]);

/**
 * Drive one case's analyze run: POST `/analyze`, then stream `/ws/progress` into
 * the shared run store so the status bar, loading bar and READY badges all read
 * one source of truth. Reconnects to an in-flight run on remount (the backend
 * replays a snapshot), and records the terminal state on the cases store.
 */
export function useAnalyzeRun(caseId: string | undefined) {
  const update = useRunStore((s) => s.update);
  const reset = useRunStore((s) => s.reset);
  const setCaseRunState = useCasesStore((s) => s.setRunState);
  const queryClient = useQueryClient();
  const socketRef = useRef<WebSocket | null>(null);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<ApiError | null>(null);

  const connect = useCallback(
    (cid: string) => {
      socketRef.current?.close();
      const ws = new WebSocket(progressWsUrl(cid));
      socketRef.current = ws;
      update(cid, { connected: true });

      ws.onmessage = (ev) => {
        let msg: ProgressEvent;
        try {
          msg = JSON.parse(ev.data as string) as ProgressEvent;
        } catch {
          return;
        }
        update(cid, {
          runId: msg.run_id ?? undefined,
          state: msg.state ?? undefined,
          percent: typeof msg.pct === "number" ? msg.pct : undefined,
          currentPass: msg.pass ?? null,
          error: msg.error ?? null,
          coverageCounts: msg.coverage_counts ?? undefined,
          skipCounts: msg.skip_counts ?? undefined,
        });
        if (msg.state && TERMINAL.has(msg.state)) {
          setCaseRunState(cid, msg.run_id ?? null, msg.state);
          // Refresh the authoritative case list so "analyzed" badges update.
          void queryClient.invalidateQueries({ queryKey: ["cases"] });
        }
      };
      ws.onclose = () => {
        if (socketRef.current === ws) {
          update(cid, { connected: false });
          socketRef.current = null;
        }
      };
      ws.onerror = () => {
        update(cid, { connected: false });
      };
    },
    [queryClient, setCaseRunState, update],
  );

  const start = useCallback(
    async (body: AnalyzeRequest = {}) => {
      if (!caseId) return;
      setStarting(true);
      setStartError(null);
      reset(caseId);
      update(caseId, { state: "pending", percent: 0 });
      try {
        const accepted = await api.analyze(caseId, body);
        update(caseId, { runId: accepted.run_id, state: "pending" });
        setCaseRunState(caseId, accepted.run_id, "pending");
        connect(caseId);
      } catch (err) {
        const apiErr = err instanceof ApiError ? err : new ApiError(0, "unknown", String(err));
        setStartError(apiErr);
        update(caseId, { state: null });
      } finally {
        setStarting(false);
      }
    },
    [caseId, connect, reset, setCaseRunState, update],
  );

  // Reconnect to an in-flight run when returning to the page.
  useEffect(() => {
    if (!caseId) return;
    const live = useRunStore.getState().runs[caseId];
    const active = live && live.state && !TERMINAL.has(live.state);
    if (active && !socketRef.current) {
      connect(caseId);
    }
    return () => {
      socketRef.current?.close();
      socketRef.current = null;
    };
  }, [caseId, connect]);

  return { start, starting, startError };
}
