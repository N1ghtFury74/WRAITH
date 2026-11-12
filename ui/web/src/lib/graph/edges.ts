/**
 * Pure edge-rendering decision logic for the sigma canvas (Round 1 A).
 *
 * The capability graph routinely has several edges between the same ordered pair
 * (e.g. User -> Group carrying GenericAll, WriteDacl AND AllExtendedRights). Drawn
 * as overlapping straight lines, their arrowheads and labels overprint — the
 * reported "AllExt…ghts" garble. These helpers decide, per edge, whether it should
 * curve (only parallel edges do, for perf) and by how much, and compute the on-arc
 * anchor where its FULL relationship label is drawn. All pure + unit-testable; the
 * sigma/graphology wiring lives in SigmaCanvas.
 */

/** Maximum absolute curvature at the extremes of a parallel-edge fan. */
export const CURVE_SPREAD = 0.4;

/**
 * Signed curvature for one edge in a parallel bundle, symmetric around zero.
 *
 * ``index`` runs ``0..maxIndex`` (from {@link indexParallelEdgesIndex}); the bundle
 * is fanned evenly to both sides so each sibling gets its own arc (and therefore its
 * own, non-overlapping, label anchor). A lone edge (``maxIndex <= 0``) gets 0.
 *
 * @returns a curvature in ``[-CURVE_SPREAD, +CURVE_SPREAD]``.
 */
export function curvatureFor(index: number, maxIndex: number): number {
  if (maxIndex <= 0) return 0;
  const t = index / maxIndex; // 0..1
  return (t - 0.5) * 2 * CURVE_SPREAD; // -SPREAD..+SPREAD
}

/**
 * The sigma edge "type" for an edge given its parallel-bundle max index.
 * Only bundles (``parallelMaxIndex > 0``) curve; singletons stay the cheap built-in
 * straight "arrow" program (no WebGL curve cost on the common case).
 */
export function edgeType(parallelMaxIndex: number | undefined): "curve" | "arrow" {
  return typeof parallelMaxIndex === "number" && parallelMaxIndex > 0 ? "curve" : "arrow";
}

export type Anchor = { x: number; y: number };

/**
 * The on-arc label anchor for an edge, mirroring @sigma/edge-curve's own label
 * geometry so a curved edge's label sits on its arc (and parallel siblings' labels
 * separate). For a straight edge (``curvature === 0``) this is the midpoint nudged
 * just off the line. Coordinates are whatever space the inputs are in (the canvas
 * passes viewport pixels). ``size`` is the edge thickness.
 *
 * Returns the midpoint unchanged when the endpoints coincide (guards /0).
 */
export function edgeLabelAnchor(
  sx: number,
  sy: number,
  tx: number,
  ty: number,
  size: number,
  curvature: number,
): Anchor {
  const ltr = sx < tx;
  const sourceX = ltr ? sx : tx;
  const sourceY = ltr ? sy : ty;
  const targetX = ltr ? tx : sx;
  const targetY = ltr ? ty : sy;
  const centerX = (sourceX + targetX) / 2;
  const centerY = (sourceY + targetY) / 2;
  const diffX = targetX - sourceX;
  const diffY = targetY - sourceY;
  const diff = Math.sqrt(diffX * diffX + diffY * diffY);
  if (diff === 0) return { x: centerX, y: centerY };
  const orientation = ltr ? 1 : -1;
  let anchorX = centerX + diffY * curvature * orientation;
  let anchorY = centerY - diffX * curvature * orientation;
  const offset = size * 0.7 + 5;
  anchorX += (offset * diffY) / diff;
  anchorY -= (offset * diffX) / diff;
  return { x: anchorX, y: anchorY };
}
