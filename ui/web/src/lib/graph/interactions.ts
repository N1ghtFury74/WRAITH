/**
 * Pure, renderer-agnostic decision logic for the Capability Graph canvas.
 * Extracted from SigmaCanvas so the branchy rules (when to preserve positions on
 * an expansion, when an edge shows its relationship label, how a new node is
 * nudged beside its parent) are unit-testable without a WebGL context.
 */

export type Pos = { x: number; y: number };

/**
 * Deterministic small offset for a newly-expanded node placed near its parent
 * (so an expansion fans out instead of stacking). Same id → same offset, and the
 * radius is bounded so newcomers land in a readable ring around the anchor.
 */
export function jitter(id: string): Pos {
  let h = 0;
  for (let i = 0; i < id.length; i += 1) h = (h * 31 + id.charCodeAt(i)) | 0;
  const a = ((Math.abs(h) % 360) * Math.PI) / 180;
  const r = 45 + (Math.abs(h) % 45);
  return { x: Math.cos(a) * r, y: Math.sin(a) * r };
}

/**
 * Should this rebuild PRESERVE already-placed node positions (an interactive
 * walk expansion) rather than lay the whole graph out afresh?
 *
 * Only when the page explicitly says it was an expansion (`expandMode`): a
 * same-identity superset produced by a *filter* change must NOT be mistaken for
 * a walk, or the newcomers would be dumped beside the old nodes without a real
 * layout. Server-laid and path views always lay out fresh; so does the very
 * first render (no remembered positions) and anything over the client cap.
 */
export function isIncrementalLayout(p: {
  expandMode: boolean;
  variant: "graph" | "path";
  useServer: boolean;
  prevCount: number;
  nodeCount: number;
  maxNodes: number;
}): boolean {
  return (
    p.expandMode &&
    p.variant === "graph" &&
    !p.useServer &&
    p.prevCount > 0 &&
    p.nodeCount > 0 &&
    p.nodeCount <= p.maxNodes
  );
}

/**
 * Should an edge render its relationship-kind label this frame?
 * - isolation (single attack path): only the edges on the isolated path;
 * - focus (hovering/selecting a node): only that node's incident edges;
 * - otherwise: path views and the "show all labels" toggle.
 * The clean default (no focus, no toggle, not a path) is NO edge labels.
 */
export function shouldShowEdgeLabel(p: {
  isolating: boolean;
  isolatedOn: boolean;
  focusActive: boolean;
  focusedOn: boolean;
  isPath: boolean;
  showAll: boolean;
}): boolean {
  if (p.isolating) return p.isolatedOn;
  if (p.focusActive) return p.focusedOn;
  return p.isPath || p.showAll;
}

/**
 * Edge count past which "show all labels" is genuinely unreadable even with curves,
 * so the toggle falls back to focused-neighbourhood labels (research 08 §2.2).
 */
export const SHOW_ALL_EDGE_CAP = 180;

export interface ShowAllGate {
  /** Whether "show all" may actually label every visible edge this frame. */
  allowed: boolean;
  /** Honest reason shown in the status overlay when the gate falls back (else null). */
  reason: string | null;
}

/**
 * Gate the global "show all edge labels" toggle by the visible-edge count. At or
 * below the cap it labels all; past it, it falls back to focus-only labels and
 * returns the reason so the UI can state WHY (honesty rule — never silently render
 * thousands of overlapping labels).
 */
export function showAllEdgeLabelGate(
  visibleEdgeCount: number,
  cap: number = SHOW_ALL_EDGE_CAP,
): ShowAllGate {
  if (visibleEdgeCount <= cap) return { allowed: true, reason: null };
  return {
    allowed: false,
    reason: `too many edges (${visibleEdgeCount}) to label all — labelling the focused neighbourhood only`,
  };
}
