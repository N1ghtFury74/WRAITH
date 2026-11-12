import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { Check, ChevronsUpDown, Circle, Monitor, Moon, Plus, Search, Sun } from "lucide-react";
import { useNavigate, useParams } from "react-router-dom";

import { Logo } from "@/components/shell/Logo";
import { Badge } from "@/components/ui/badge";
import { useCaseList } from "@/hooks/useCaseList";
import { DENSITY_ORDER, useDensity, type Density } from "@/hooks/useDensity";
import { useTheme, type ThemePref } from "@/hooks/useTheme";
import type { CaseListItem } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useLiveRun } from "@/store/run";

const THEME_ICON: Record<ThemePref, typeof Sun> = { light: Sun, dark: Moon, system: Monitor };
const THEME_LABEL: Record<ThemePref, string> = {
  light: "Theme: light (click for dark)",
  dark: "Theme: dark (click for system)",
  system: "Theme: system (click for light)",
};

/** A− / A / A+ glyph + accessible label for each density stop. */
const DENSITY_META: Record<Density, { glyph: string; label: string }> = {
  compact: { glyph: "A−", label: "Compact text size (smaller)" },
  normal: { glyph: "A", label: "Normal text size (default)" },
  comfortable: { glyph: "A+", label: "Comfortable text size (larger)" },
};

/**
 * Text-size control (A− / A / A+): scales the whole UI via the root font-size,
 * independent of OS / browser zoom. Persisted; applied pre-paint by the inline
 * head script so there is no flash. A segmented group of three toggle buttons.
 */
function DensityControl() {
  const { density, setDensity } = useDensity();
  return (
    <div
      role="group"
      aria-label="Text size"
      className="flex h-8 items-center rounded-md border border-border p-0.5"
    >
      {DENSITY_ORDER.map((d) => {
        const active = d === density;
        return (
          <button
            key={d}
            type="button"
            onClick={() => setDensity(d)}
            aria-pressed={active}
            aria-label={DENSITY_META[d].label}
            title={DENSITY_META[d].label}
            className={cn(
              "flex h-full min-w-7 items-center justify-center rounded px-1.5 text-body font-medium leading-none tabular-nums transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background",
              active
                ? "bg-surface-raised text-foreground"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {DENSITY_META[d].glyph}
          </button>
        );
      })}
    </div>
  );
}

/** Three-state theme cycle (doc 10 §2.2): light → dark → system. Persisted. */
function ThemeToggle() {
  const { pref, cycle } = useTheme();
  const Icon = THEME_ICON[pref];
  return (
    <button
      type="button"
      onClick={cycle}
      aria-label={THEME_LABEL[pref]}
      title={THEME_LABEL[pref]}
      className="flex size-8 items-center justify-center rounded-md border border-border text-muted-foreground transition-colors hover:bg-surface-raised hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
    >
      <Icon className="size-4" />
    </button>
  );
}

function destFor(c: Pick<CaseListItem, "case_id" | "analyzed">): string {
  return `/case/${encodeURIComponent(c.case_id)}/${c.analyzed ? "graph" : "ingest"}`;
}

/** Top bar (doc 13 §3): product mark · case selector · search · live indicator. */
export function TopBar() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const casesQuery = useCaseList();
  const live = useLiveRun(caseId);

  const cases = casesQuery.data ?? [];
  const running = live.state === "running" || live.state === "pending";

  return (
    <header className="flex h-14 shrink-0 items-center gap-4 border-b border-border bg-surface px-4">
      <button
        onClick={() => navigate("/cases")}
        className="flex items-center gap-2.5 tracking-tight"
        title="WRAITH — Know what the attacker knows. Offline Active Directory forensics."
      >
        <Logo className="size-7 shrink-0" />
        <span className="flex min-w-0 flex-col items-start leading-tight">
          <span className="text-body font-semibold text-foreground">WRAITH</span>
          <span className="hidden truncate text-micro font-normal text-muted-foreground lg:block">
            Know what the attacker knows.
          </span>
        </span>
      </button>

      <div className="h-6 w-px bg-border" />

      {/* Case selector */}
      <DropdownMenu.Root>
        <DropdownMenu.Trigger asChild>
          <button
            className="flex items-center gap-2 rounded-md border border-border bg-surface-raised px-3 py-1.5 text-body hover:bg-muted"
            aria-label="Select case"
          >
            <span className="text-muted-foreground">Case</span>
            {caseId ? (
              <span className="font-mono text-body-sm text-foreground">{caseId}</span>
            ) : (
              <span className="text-muted-foreground">No case selected</span>
            )}
            <ChevronsUpDown className="size-3.5 text-muted-foreground" />
          </button>
        </DropdownMenu.Trigger>
        <DropdownMenu.Portal>
          <DropdownMenu.Content
            align="start"
            sideOffset={6}
            className="z-50 max-h-80 min-w-[16rem] overflow-y-auto animate-fade-in rounded-md border border-border bg-surface-overlay p-1 shadow-overlay"
          >
            <DropdownMenu.Label className="eyebrow px-2 py-1.5">
              Cases ({cases.length})
            </DropdownMenu.Label>
            {cases.length === 0 ? (
              <div className="px-2 py-2 text-caption text-muted-foreground">No cases yet.</div>
            ) : (
              cases.map((c) => (
                <DropdownMenu.Item
                  key={c.case_id}
                  onSelect={() => navigate(destFor(c))}
                  className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-body outline-none hover:bg-muted data-[highlighted]:bg-muted"
                >
                  <Check className={cn("size-3.5", c.case_id === caseId ? "opacity-100" : "opacity-0")} />
                  <span className="min-w-0 flex-1 truncate font-mono text-caption">{c.case_id}</span>
                  {c.analyzed ? <Badge variant="available">analyzed</Badge> : null}
                </DropdownMenu.Item>
              ))
            )}
            <DropdownMenu.Separator className="my-1 h-px bg-border" />
            <DropdownMenu.Item
              onSelect={() => navigate("/cases")}
              className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-body text-accent outline-none hover:bg-muted data-[highlighted]:bg-muted"
            >
              <Plus className="size-3.5" />
              New / manage cases
            </DropdownMenu.Item>
          </DropdownMenu.Content>
        </DropdownMenu.Portal>
      </DropdownMenu.Root>

      {/* Global search (placeholder for now; wired in a later FE) */}
      <div className="relative ml-2 hidden max-w-md flex-1 md:block">
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <input
          disabled
          placeholder="Search…"
          title="Global search is available in a later release"
          className="h-9 w-full cursor-not-allowed rounded-md border border-border bg-surface-raised/60 pl-9 pr-3 text-body text-muted-foreground placeholder:text-muted-foreground"
        />
      </div>

      {/* Right cluster: text-size + theme toggle + live-ingest indicator */}
      <div className="ml-auto flex items-center gap-3">
        <DensityControl />
        <ThemeToggle />
        <div className="flex items-center gap-2 text-caption">
          <Circle
          className={cn(
            "size-2.5 fill-current",
            running
              ? "animate-pulse text-accent"
              : live.state === "done"
                ? "text-available"
                : live.state === "failed"
                  ? "text-unavailable"
                  : "text-muted-foreground",
          )}
        />
        <span className="tabular-nums text-muted-foreground">
          {running
            ? `analyzing ${live.percent}%`
            : live.state === "done"
              ? "idle · analyzed"
              : live.state === "failed"
                ? "last run failed"
                : "idle"}
          </span>
        </div>
      </div>
    </header>
  );
}
