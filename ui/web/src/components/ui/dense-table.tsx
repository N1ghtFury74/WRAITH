import { cn } from "@/lib/utils";

/**
 * Shared dense-table primitive (doc 10 §7.3): a sticky header row, ~32px rows,
 * hairline `--border` separators, `tabular-nums` on numeric columns, and a
 * `--surface-raised` row hover. Var-driven, so it themes for free. Consumed by
 * dossier members / risk factors / long lists. Compose with the semantic
 * sub-elements below; keep it presentational (sorting/filtering stays in callers).
 */
export function DenseTable({
  className,
  children,
  maxHeightClass,
}: {
  className?: string;
  children: React.ReactNode;
  /** When set (e.g. `max-h-80`), the body scrolls under the sticky header. */
  maxHeightClass?: string;
}) {
  return (
    <div
      className={cn(
        "overflow-auto rounded-md border border-border",
        maxHeightClass,
        className,
      )}
    >
      <table className="w-full border-collapse text-left text-body-sm">{children}</table>
    </div>
  );
}

/** Sticky header row (stays visible while the body scrolls). */
export function DenseHead({ children }: { children: React.ReactNode }) {
  return (
    <thead className="sticky top-0 z-10 bg-surface-raised">
      <tr>{children}</tr>
    </thead>
  );
}

export function DenseTh({
  children,
  className,
  numeric,
}: {
  children?: React.ReactNode;
  className?: string;
  numeric?: boolean;
}) {
  return (
    <th
      className={cn(
        "h-8 whitespace-nowrap border-b border-border px-2.5 text-micro font-semibold uppercase tracking-[0.06em] text-muted-foreground",
        numeric && "text-right tabular-nums",
        className,
      )}
    >
      {children}
    </th>
  );
}

export function DenseBody({ children }: { children: React.ReactNode }) {
  return <tbody>{children}</tbody>;
}

export function DenseRow({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <tr className={cn("border-b border-border/60 last:border-0 hover:bg-surface-raised/60", className)}>
      {children}
    </tr>
  );
}

export function DenseCell({
  children,
  className,
  numeric,
}: {
  children?: React.ReactNode;
  className?: string;
  numeric?: boolean;
}) {
  return (
    <td
      className={cn(
        "h-8 px-2.5 align-middle text-foreground",
        numeric && "text-right font-mono tabular-nums",
        className,
      )}
    >
      {children}
    </td>
  );
}
