import type { DossierEdge } from "@/lib/api";

/**
 * Pure dossier list helpers (doc 10 §5.2) — grouping/filtering/summary logic kept
 * out of the view so it is unit-testable and deterministic. No React, no I/O.
 */

/** One controller principal and every inbound ACE it holds over the subject. */
export interface ControllerGroup {
  /** The controlling party (resolved label + id + kind + Tier-0 flag). */
  controller: DossierEdge["other"];
  /** All ACE rows this principal holds (sorted by right kind). */
  edges: DossierEdge[];
  /** Unique right kinds held, sorted (rendered as sub-chips). */
  rights: string[];
  /** True when the controller is a Tier-0 / high-value principal. */
  isTier0: boolean;
}

/**
 * Collapse inbound ACEs so one principal holding many rights ("User X: GenericAll
 * + WriteDacl + WriteOwner") becomes ONE group instead of many rows (doc 10 §5.2).
 * Groups are ordered Tier-0-controllers-first, then by controller label; the
 * right kinds and member edges inside each group are sorted. Deterministic.
 *
 * @param edges inbound ACE rows (each with a resolved `other` controller party)
 * @returns one {@link ControllerGroup} per distinct controller principal
 */
export function groupInboundByController(edges: DossierEdge[]): ControllerGroup[] {
  const byController = new Map<string, DossierEdge[]>();
  for (const e of edges) {
    const key = e.other.node_id;
    (byController.get(key) ?? byController.set(key, []).get(key)!).push(e);
  }
  const groups: ControllerGroup[] = [];
  for (const list of byController.values()) {
    const sorted = [...list].sort((a, b) => a.kind.localeCompare(b.kind));
    const rights = [...new Set(sorted.map((e) => e.kind))].sort();
    groups.push({
      controller: sorted[0].other,
      edges: sorted,
      rights,
      isTier0: Boolean(sorted[0].other.is_tier0),
    });
  }
  return groups.sort(
    (a, b) =>
      Number(b.isTier0) - Number(a.isTier0) || a.controller.label.localeCompare(b.controller.label),
  );
}

/**
 * Case-insensitive substring filter over `label` (and `kind`) — the client-side
 * "filter members…" box. An empty/whitespace term returns the list unchanged.
 */
export function filterByLabel<T extends { label: string; kind: string }>(
  items: T[],
  term: string,
): T[] {
  const q = term.trim().toLowerCase();
  if (q === "") return items;
  return items.filter(
    (i) => i.label.toLowerCase().includes(q) || i.kind.toLowerCase().includes(q),
  );
}

/** One `{ kind, count }` tally in a count breakdown. */
export interface KindCount {
  kind: string;
  count: number;
}

/**
 * Count items by `kind`, ordered by count desc then kind asc — the "1,240
 * members: 1,190 User · 40 Computer · 10 Group" summary shown before a long list
 * so the page is useful before expansion (doc 10 §5.2). Deterministic.
 */
export function kindBreakdown<T extends { kind: string }>(items: T[]): KindCount[] {
  const counts = new Map<string, number>();
  for (const i of items) counts.set(i.kind, (counts.get(i.kind) ?? 0) + 1);
  return [...counts.entries()]
    .map(([kind, count]) => ({ kind, count }))
    .sort((a, b) => b.count - a.count || a.kind.localeCompare(b.kind));
}
