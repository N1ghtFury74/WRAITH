import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-micro font-medium leading-none transition-colors",
  {
    variants: {
      variant: {
        default: "border-border bg-surface-raised text-muted-foreground",
        accent: "border-accent/40 bg-accent/10 text-accent",
        available: "border-available/40 bg-available/10 text-available",
        degraded: "border-degraded/40 bg-degraded/10 text-degraded",
        unavailable: "border-unavailable/40 bg-unavailable/10 text-unavailable",
        // Tier-0 = a FILLED red chip (doc 10 §2.4): hue is never the sole signal,
        // so it stays unmistakable in LIGHT where red-text would collide with the
        // error red. Solid bg + white text reads in both themes (6.5:1 / high).
        tier0: "border-transparent bg-tier0 font-semibold text-white",
        required: "border-accent/50 bg-accent/15 text-accent",
        outline: "border-border text-muted-foreground",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { badgeVariants };
