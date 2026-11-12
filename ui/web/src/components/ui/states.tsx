import { AlertTriangle, Inbox, Loader2 } from "lucide-react";

import { cn } from "@/lib/utils";

/** Centered empty-state block (icon + title + hint + optional action). */
export function EmptyState({
  icon: Icon = Inbox,
  title,
  hint,
  action,
  className,
}: {
  icon?: typeof Inbox;
  title: string;
  hint?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-border bg-surface/40 px-6 py-10 text-center",
        className,
      )}
    >
      <Icon className="size-8 text-muted-foreground" />
      <div className="space-y-1">
        <p className="text-body font-medium text-foreground">{title}</p>
        {hint ? <p className="max-w-sm text-caption text-muted-foreground">{hint}</p> : null}
      </div>
      {action}
    </div>
  );
}

/** A single shimmer block for skeleton loaders. */
export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded bg-muted", className)} />;
}

/** A stack of skeleton rows (vendor-grade list/graph loading, not a bare spinner). */
export function SkeletonRows({ rows = 5, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn("space-y-2", className)}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-3">
          <Skeleton className="size-8 shrink-0 rounded-full" />
          <div className="flex-1 space-y-1.5">
            <Skeleton className="h-3 w-1/3" />
            <Skeleton className="h-2.5 w-1/2" />
          </div>
        </div>
      ))}
    </div>
  );
}

/** Inline loading row (spinner + label) — never a bare spinner. */
export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-10 text-body text-muted-foreground">
      <Loader2 className="size-4 animate-spin" />
      {label}
    </div>
  );
}

/** Inline error block (icon + message + optional retry). */
export function ErrorState({
  title = "Something went wrong",
  message,
  action,
}: {
  title?: string;
  message?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-unavailable/30 bg-unavailable/5 px-6 py-10 text-center">
      <AlertTriangle className="size-7 text-unavailable" />
      <div className="space-y-1">
        <p className="text-body font-medium text-foreground">{title}</p>
        {message ? <p className="max-w-md text-caption text-muted-foreground">{message}</p> : null}
      </div>
      {action}
    </div>
  );
}
