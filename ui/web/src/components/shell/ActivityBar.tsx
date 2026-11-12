import { Info, Lock } from "lucide-react";
import { Link, NavLink, useParams } from "react-router-dom";

import { NAV_ITEMS } from "@/components/shell/nav";
import { useCaseList } from "@/hooks/useCaseList";
import { cn } from "@/lib/utils";
import { useLiveRun } from "@/store/run";

/**
 * The primary module nav (doc 10 §4.3 — Kibana/VS-Code pattern, but LABELLED).
 * The owner asked for the module name beside each icon for easier navigation, so
 * this is a ~13rem labelled rail rather than an icon-only strip: icon + label per
 * row, always visible, never collapses. Module items sit at the top; About anchors
 * the bottom. The contextual secondary panel (Hunter Library + Filters on the
 * Graph) lives in a SEPARATE collapsible column each module renders beside this —
 * it is NOT nested here. The active item gets an accent fill + left-marker; disabled
 * items dim with a reason on hover (native title).
 */
export function ActivityBar() {
  const { caseId } = useParams();
  const live = useLiveRun(caseId);
  const casesQuery = useCaseList();
  const serverAnalyzed = casesQuery.data?.find((c) => c.case_id === caseId)?.analyzed ?? false;
  const analyzed = live.state === "done" || serverAnalyzed;

  const row =
    "relative flex items-center gap-3 rounded-md px-3 py-2 text-body transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

  return (
    <nav
      aria-label="Modules"
      className="flex w-52 shrink-0 flex-col border-r border-border bg-surface p-3"
    >
      <div className="flex flex-1 flex-col gap-1">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const disabled = !caseId || item.reserved || (item.needsAnalysis && !analyzed);
          const reason = item.reserved
            ? "Reserved — behavioral baselining arrives in a later milestone"
            : !caseId
              ? "Select a case first"
              : item.needsAnalysis && !analyzed
                ? "Available once the case is analyzed"
                : item.label;

          if (disabled) {
            return (
              <div
                key={item.segment}
                aria-disabled
                title={reason}
                className={cn(row, "cursor-not-allowed text-muted-foreground/40")}
              >
                <Icon className="size-5 shrink-0" />
                <span className="min-w-0 flex-1 truncate">{item.label}</span>
                {item.reserved ? <Lock className="size-3.5 shrink-0 text-muted-foreground/50" /> : null}
              </div>
            );
          }

          return (
            <NavLink
              key={item.segment}
              to={`/case/${encodeURIComponent(caseId!)}/${item.segment}`}
              title={item.label}
              className={({ isActive }) =>
                cn(
                  row,
                  isActive
                    ? "bg-accent/10 font-medium text-accent before:absolute before:inset-y-1.5 before:left-[-12px] before:w-0.5 before:rounded-full before:bg-accent"
                    : "text-muted-foreground hover:bg-surface-raised hover:text-foreground",
                )
              }
            >
              <Icon className="size-5 shrink-0" />
              <span className="min-w-0 flex-1 truncate">{item.label}</span>
            </NavLink>
          );
        })}
      </div>

      {/* Bottom cluster: About (profile/credits). The theme toggle lives in the
          TopBar (doc 10 §2.2) — one home only, never duplicated. */}
      <Link
        to="/about"
        title="About · author"
        className={cn(row, "text-muted-foreground hover:bg-surface-raised hover:text-foreground")}
      >
        <Info className="size-5 shrink-0" />
        <span className="min-w-0 flex-1 truncate">About</span>
      </Link>
    </nav>
  );
}
