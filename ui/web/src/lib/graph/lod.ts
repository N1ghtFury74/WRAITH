/**
 * Camera-ratio level-of-detail (LOD) for the sigma canvas (Round 1 B).
 *
 * sigma's camera ``ratio`` is >1 when zoomed out, <1 when zoomed in. When the user
 * zooms far out, resolving every edge- and node-label turns the view into a
 * hairball. These pure thresholds decide what detail to keep at a given ratio; the
 * canvas listens to the camera ``updated`` event, recomputes this, and re-runs its
 * reducers so labels drop out at distance and return on zoom-in.
 */

export interface LodThresholds {
  /** Above this camera ratio (more zoomed out), edge labels are suppressed. */
  hideEdgeLabels: number;
  /** Above this camera ratio, node labels are suppressed too (only forced ones stay). */
  hideNodeLabels: number;
  /**
   * At/below this camera ratio (zoomed in close, few nodes on screen), EVERY node
   * label is revealed — not just the forced marks. Above it the default view stays
   * clean: only Tier-0 / principal hubs / selected / focused nodes carry a label,
   * so structural containers and deleted/DNS leaves don't overprint (readability
   * fix). The "Show all labels" toolbar toggle reveals them at any zoom.
   */
  showAllNodeLabels: number;
}

/** Tuned breakpoints (UX pass): edge labels drop first, node labels much later. */
export const DEFAULT_LOD: LodThresholds = {
  hideEdgeLabels: 1.8,
  hideNodeLabels: 3.5,
  showAllNodeLabels: 0.65,
};

export interface LodState {
  /** Render edge labels at this zoom (subject to the usual focus/show-all gating). */
  edgeLabels: boolean;
  /** Render node labels at this zoom (forced Tier-0/selected labels still show). */
  nodeLabels: boolean;
  /** Reveal ALL node labels (not only forced marks) — true only when zoomed in close. */
  nodeLabelsAll: boolean;
}

/**
 * Resolve the LOD state for a camera ratio. Monotonic: zooming out only ever drops
 * detail, zooming in only ever restores it. Edge labels vanish before node labels;
 * the full set of node labels is revealed only once zoomed in close.
 */
export function lodFor(ratio: number, thresholds: LodThresholds = DEFAULT_LOD): LodState {
  return {
    edgeLabels: ratio <= thresholds.hideEdgeLabels,
    nodeLabels: ratio <= thresholds.hideNodeLabels,
    nodeLabelsAll: ratio <= thresholds.showAllNodeLabels,
  };
}
