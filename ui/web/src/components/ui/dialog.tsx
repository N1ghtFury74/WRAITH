import * as DialogPrimitive from "@radix-ui/react-dialog";
import { X } from "lucide-react";

import { cn } from "@/lib/utils";

export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogClose = DialogPrimitive.Close;

/** Centered modal content over a dimmed overlay (dark-themed, offline, no deps). */
export function DialogContent({
  className,
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm data-[state=open]:animate-fade-in" />
      <DialogPrimitive.Content
        className={cn(
          "fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2",
          "rounded-lg border border-border bg-surface-overlay p-5 shadow-overlay",
          "data-[state=open]:animate-fade-in",
          className,
        )}
      >
        {children}
        <DialogPrimitive.Close
          aria-label="Close"
          className="absolute right-3 top-3 text-muted-foreground hover:text-foreground focus-visible:ring-1 focus-visible:ring-ring"
        >
          <X className="size-4" />
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}

export function DialogTitle({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <DialogPrimitive.Title className={cn("text-body font-semibold text-foreground", className)}>
      {children}
    </DialogPrimitive.Title>
  );
}

export function DialogDescription({
  className,
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <DialogPrimitive.Description className={cn("mt-1 text-caption text-muted-foreground", className)}>
      {children}
    </DialogPrimitive.Description>
  );
}
