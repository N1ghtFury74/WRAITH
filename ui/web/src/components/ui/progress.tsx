import { cn } from "@/lib/utils";

interface ProgressProps {
  /** 0..100. Pass `null` for an indeterminate (unknown-duration) bar. */
  value: number | null;
  className?: string;
  tone?: "accent" | "available" | "degraded" | "unavailable";
}

const TONE: Record<NonNullable<ProgressProps["tone"]>, string> = {
  accent: "bg-accent",
  available: "bg-available",
  degraded: "bg-degraded",
  unavailable: "bg-unavailable",
};

/** A linear progress bar with determinate + indeterminate modes. */
export function Progress({ value, className, tone = "accent" }: ProgressProps) {
  const indeterminate = value === null;
  return (
    <div
      className={cn(
        "relative h-2 w-full overflow-hidden rounded-full bg-muted",
        className,
      )}
      role="progressbar"
      aria-valuenow={indeterminate ? undefined : Math.round(value)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      {indeterminate ? (
        <div className={cn("absolute inset-y-0 w-1/4 rounded-full animate-indeterminate", TONE[tone])} />
      ) : (
        <div
          className={cn("h-full rounded-full transition-[width] duration-300 ease-out", TONE[tone])}
          style={{ width: `${Math.max(0, Math.min(100, value))}%` }}
        />
      )}
    </div>
  );
}
