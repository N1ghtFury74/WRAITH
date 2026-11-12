import * as DialogPrimitive from "@radix-ui/react-dialog";
import { PanelLeftClose, PanelLeftOpen, X, type LucideIcon } from "lucide-react";
import { useEffect, useState } from "react";

import { useMediaQuery } from "@/hooks/useMediaQuery";
import { readLs, writeLs } from "@/lib/storage";
import { cn } from "@/lib/utils";

export interface PanelTab {
  id: string;
  label: string;
  icon: LucideIcon;
  content: React.ReactNode;
}

interface Props {
  /** Persist key suffix: collapse state saved at `wraith.panel.<moduleKey>.open`. */
  moduleKey: string;
  /** Panel heading (e.g. "Capability Graph"). */
  title: string;
  tabs: PanelTab[];
  /** Initial active tab id (defaults to the first tab). */
  defaultTabId?: string;
}

/**
 * The contextual secondary panel (doc 10 §4.3): a 280px collapsible column that
 * sits beside the activity bar and is tabbed per module. On the Graph it holds
 * Hunts + Filters — one left column, not a double rail with a nested catalog.
 *
 * - Wide screens: an inline column; collapses to a thin icon strip (click a tab
 *   icon to re-open to that tab). Collapse is persisted at
 *   `wraith.panel.<moduleKey>.open` (try/catch via readLs/writeLs).
 * - Narrow screens (`< md`): an off-canvas Radix Dialog flyout opened from a
 *   floating button, so the graph canvas keeps the full width.
 *
 * Only one of {inline, flyout} mounts at a time (driven by `useMediaQuery`) so a
 * tab's content never double-mounts.
 */
export function SecondaryPanel({ moduleKey, title, tabs, defaultTabId }: Props) {
  const storageKey = `wraith.panel.${moduleKey}.open`;
  const isNarrow = useMediaQuery("(max-width: 767px)");

  const [open, setOpen] = useState<boolean>(() => readLs<boolean>(storageKey, true));
  const [activeId, setActiveId] = useState<string>(defaultTabId ?? tabs[0]?.id ?? "");
  const [flyoutOpen, setFlyoutOpen] = useState(false);

  useEffect(() => writeLs(storageKey, open), [storageKey, open]);

  const active = tabs.find((t) => t.id === activeId) ?? tabs[0];
  if (!active) return null;

  const tabStrip = (
    <div className="flex items-center gap-1 border-b border-border px-2" role="tablist">
      {tabs.map((t) => {
        const Icon = t.icon;
        const on = t.id === active.id;
        return (
          <button
            key={t.id}
            role="tab"
            aria-selected={on}
            onClick={() => setActiveId(t.id)}
            className={cn(
              "flex items-center gap-1.5 border-b-2 px-2 py-2 text-caption font-medium transition-colors",
              on
                ? "border-accent text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            <Icon className="size-3.5" />
            {t.label}
          </button>
        );
      })}
    </div>
  );

  const body = (
    <div className="min-h-0 flex-1 overflow-y-auto p-3" role="tabpanel">
      {active.content}
    </div>
  );

  // ─── Narrow: off-canvas flyout ───────────────────────────────────────────
  if (isNarrow) {
    return (
      <DialogPrimitive.Root open={flyoutOpen} onOpenChange={setFlyoutOpen}>
        <DialogPrimitive.Trigger asChild>
          <button
            type="button"
            aria-label={`Open ${title} panel`}
            className="fixed bottom-10 left-16 z-30 flex items-center gap-1.5 rounded-md border border-border bg-surface-overlay/95 px-2.5 py-1.5 text-caption text-foreground shadow-overlay backdrop-blur"
          >
            <PanelLeftOpen className="size-4" /> {title}
          </button>
        </DialogPrimitive.Trigger>
        <DialogPrimitive.Portal>
          <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm data-[state=open]:animate-fade-in" />
          <DialogPrimitive.Content
            className="fixed inset-y-0 left-0 z-50 flex w-[300px] max-w-[85vw] flex-col bg-surface shadow-overlay data-[state=open]:animate-fade-in"
            aria-describedby={undefined}
          >
            <div className="flex items-center justify-between border-b border-border px-3 py-2.5">
              <DialogPrimitive.Title className="text-caption font-semibold uppercase tracking-[0.06em] text-muted-foreground">
                {title}
              </DialogPrimitive.Title>
              <DialogPrimitive.Close aria-label="Close panel" className="text-muted-foreground hover:text-foreground">
                <X className="size-4" />
              </DialogPrimitive.Close>
            </div>
            {tabStrip}
            {body}
          </DialogPrimitive.Content>
        </DialogPrimitive.Portal>
      </DialogPrimitive.Root>
    );
  }

  // ─── Wide: collapsed icon strip ──────────────────────────────────────────
  if (!open) {
    return (
      <aside className="flex w-11 shrink-0 flex-col items-center gap-1 border-r border-border bg-surface/60 py-2">
        <button
          type="button"
          aria-label="Expand panel"
          title="Expand panel"
          onClick={() => setOpen(true)}
          className="flex size-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-surface-raised hover:text-foreground focus-visible:ring-1 focus-visible:ring-ring"
        >
          <PanelLeftOpen className="size-4" />
        </button>
        <div className="my-1 h-px w-6 bg-border" />
        {tabs.map((t) => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              type="button"
              aria-label={`Open ${t.label}`}
              title={t.label}
              onClick={() => {
                setActiveId(t.id);
                setOpen(true);
              }}
              className="flex size-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-surface-raised hover:text-foreground focus-visible:ring-1 focus-visible:ring-ring"
            >
              <Icon className="size-4" />
            </button>
          );
        })}
      </aside>
    );
  }

  // ─── Wide: open inline column ────────────────────────────────────────────
  return (
    <aside className="flex w-[280px] shrink-0 flex-col border-r border-border bg-surface/60">
      <div className="flex items-center justify-between px-3 py-2.5">
        <h2 className="text-caption font-semibold uppercase tracking-[0.06em] text-muted-foreground">{title}</h2>
        <button
          type="button"
          aria-label="Collapse panel"
          title="Collapse panel"
          onClick={() => setOpen(false)}
          className="text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-1 focus-visible:ring-ring"
        >
          <PanelLeftClose className="size-4" />
        </button>
      </div>
      {tabStrip}
      {body}
    </aside>
  );
}
