import { forwardRef } from "react";

import { cn } from "@/lib/utils";

export const Label = forwardRef<HTMLLabelElement, React.LabelHTMLAttributes<HTMLLabelElement>>(
  ({ className, ...props }, ref) => (
    <label
      ref={ref}
      className={cn("text-caption font-medium text-muted-foreground", className)}
      {...props}
    />
  ),
);
Label.displayName = "Label";
