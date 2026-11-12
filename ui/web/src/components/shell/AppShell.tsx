import { Outlet } from "react-router-dom";

import { ActivityBar } from "@/components/shell/ActivityBar";
import { StatusBar } from "@/components/shell/StatusBar";
import { TopBar } from "@/components/shell/TopBar";

/**
 * The fixed shell frame (doc 10 §4.3): top bar · 56px activity bar · content ·
 * status bar. The per-module contextual secondary panel (e.g. the Graph's
 * Hunts/Filters column) is rendered by each page just inside the content region,
 * so it sits directly beside the activity bar — not nested in the rail.
 */
export function AppShell() {
  return (
    <div className="flex h-full flex-col overflow-hidden">
      <TopBar />
      <div className="flex min-h-0 flex-1">
        <ActivityBar />
        <main className="min-w-0 flex-1 overflow-y-auto bg-background">
          <Outlet />
        </main>
      </div>
      <StatusBar />
    </div>
  );
}
