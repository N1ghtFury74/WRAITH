import * as TooltipPrimitive from "@radix-ui/react-tooltip";

import { cn } from "@/lib/utils";

/** Wrap the app (or a subtree) once; `delayDuration` applies to all tooltips. */
export const TooltipProvider = TooltipPrimitive.Provider;
export const TooltipRoot = TooltipPrimitive.Root;
export const TooltipTrigger = TooltipPrimitive.Trigger;

/** Floating label content (var-driven overlay — themes for free, offline). */
export function TooltipContent({
  className,
  side = "right",
  sideOffset = 6,
  children,
}: {
  className?: string;
  side?: "top" | "right" | "bottom" | "left";
  sideOffset?: number;
  children: React.ReactNode;
}) {
  return (
    <TooltipPrimitive.Portal>
      <TooltipPrimitive.Content
        side={side}
        sideOffset={sideOffset}
        className={cn(
          "z-50 select-none rounded-md border border-border bg-surface-overlay px-2 py-1 text-caption text-foreground shadow-overlay",
          "data-[state=delayed-open]:animate-fade-in",
          className,
        )}
      >
        {children}
      </TooltipPrimitive.Content>
    </TooltipPrimitive.Portal>
  );
}

/**
 * Convenience single-label tooltip: wrap a trigger, pass the label. For the
 * common icon-button case. Must sit under a {@link TooltipProvider}.
 */
export function Tooltip({
  label,
  side = "right",
  children,
}: {
  label: React.ReactNode;
  side?: "top" | "right" | "bottom" | "left";
  children: React.ReactNode;
}) {
  return (
    <TooltipRoot>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent side={side}>{label}</TooltipContent>
    </TooltipRoot>
  );
}
