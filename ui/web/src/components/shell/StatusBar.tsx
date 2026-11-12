import { useParams } from "react-router-dom";

import { Progress } from "@/components/ui/progress";
import { useLiveRun } from "@/store/run";

/** Bottom status bar (doc 13 §3): run progress + offline posture. */
export function StatusBar() {
  const { caseId } = useParams();
  const live = useLiveRun(caseId);
  const running = live.state === "running" || live.state === "pending";

  return (
    <footer className="flex h-7 shrink-0 items-center gap-4 border-t border-border bg-surface px-4 text-micro text-muted-foreground">
      <div className="flex min-w-0 flex-1 items-center gap-3">
        {running ? (
          <>
            <span className="shrink-0">
              {live.currentPass ? `pass: ${live.currentPass}` : "starting…"}
            </span>
            <div className="max-w-xs flex-1">
              <Progress value={live.percent} />
            </div>
            <span className="shrink-0 font-mono tabular-nums">{live.percent}%</span>
          </>
        ) : live.state === "done" ? (
          <span className="text-available">analysis complete</span>
        ) : live.state === "failed" ? (
          <span className="text-unavailable">analysis failed: {live.error ?? "unknown error"}</span>
        ) : (
          <span>ready</span>
        )}
      </div>
      <span className="shrink-0 font-mono uppercase tracking-wider text-muted-foreground">
        offline
      </span>
    </footer>
  );
}
