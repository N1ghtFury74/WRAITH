/**
 * Pure overflow helpers for dossier lists (doc 10 §5.2). A privileged principal
 * can control thousands of objects; dumping every name inline reads as a wall and
 * a bare "+N more" with no toggle is a dead end. These helpers split a list into a
 * visible head + an honest hidden count so the view can render a clean
 * show-all/collapse affordance while the REAL total always stays on screen.
 * No React, no I/O — unit-testable and deterministic.
 */

/** The result of capping a list to a visible head (see {@link capList}). */
export interface Capped<T> {
  /** The items to render this frame (head when collapsed, all when expanded). */
  shown: T[];
  /** How many items are hidden RIGHT NOW (0 when expanded or within the cap). */
  hidden: number;
  /** Whether the list ever overflows the cap — i.e. a toggle should be offered. */
  hasMore: boolean;
}

/**
 * Cap a list to its first `cap` items unless `expanded`, reporting the hidden
 * count and whether a toggle is warranted. A non-positive cap is treated as 0
 * (collapse to nothing but still offer the toggle when there are items).
 *
 * @param items  the full list (never mutated)
 * @param cap    how many to show while collapsed
 * @param expanded  when true, show everything (hidden becomes 0)
 */
export function capList<T>(items: T[], cap: number, expanded: boolean): Capped<T> {
  const limit = Math.max(0, Math.floor(cap));
  const hasMore = items.length > limit;
  if (expanded || !hasMore) {
    return { shown: items, hidden: 0, hasMore };
  }
  return { shown: items.slice(0, limit), hidden: items.length - limit, hasMore };
}

/**
 * The label for a show-all/collapse toggle: "Show all 2,058" when collapsed,
 * "Show fewer" when expanded. The total is thousands-grouped so big counts stay
 * legible. Kept here (not in the view) so the copy is testable.
 */
export function expandToggleLabel(total: number, expanded: boolean): string {
  return expanded ? "Show fewer" : `Show all ${total.toLocaleString("en-US")}`;
}
