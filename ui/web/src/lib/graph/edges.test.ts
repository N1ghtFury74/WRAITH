import { describe, expect, it } from "vitest";

import { curvatureFor, CURVE_SPREAD, edgeLabelAnchor, edgeType } from "./edges";

describe("curvatureFor", () => {
  it("is 0 for a lone edge (maxIndex <= 0)", () => {
    expect(curvatureFor(0, 0)).toBe(0);
    expect(curvatureFor(3, -1)).toBe(0);
  });

  it("fans a bundle symmetrically around 0", () => {
    // two parallels: index 0 and 1 bow to opposite sides, equal magnitude.
    expect(curvatureFor(0, 1)).toBeCloseTo(-CURVE_SPREAD);
    expect(curvatureFor(1, 1)).toBeCloseTo(CURVE_SPREAD);
    // three parallels: middle edge is ~straight.
    expect(curvatureFor(1, 2)).toBeCloseTo(0);
  });

  it("stays within [-CURVE_SPREAD, +CURVE_SPREAD]", () => {
    for (let max = 1; max <= 6; max += 1) {
      for (let i = 0; i <= max; i += 1) {
        const c = curvatureFor(i, max);
        expect(c).toBeGreaterThanOrEqual(-CURVE_SPREAD - 1e-9);
        expect(c).toBeLessThanOrEqual(CURVE_SPREAD + 1e-9);
      }
    }
  });
});

describe("edgeType", () => {
  it("curves only parallel bundles, keeps singletons straight", () => {
    expect(edgeType(0)).toBe("arrow");
    expect(edgeType(undefined)).toBe("arrow");
    expect(edgeType(1)).toBe("curve");
    expect(edgeType(4)).toBe("curve");
  });
});

describe("edgeLabelAnchor", () => {
  it("returns the midpoint (off-line) for a straight edge", () => {
    const a = edgeLabelAnchor(0, 0, 100, 0, 1, 0);
    // centered on x, nudged off the line on y (perpendicular offset)
    expect(a.x).toBeCloseTo(50);
    expect(Math.abs(a.y)).toBeGreaterThan(0);
  });

  it("separates parallel siblings (opposite curvatures → different anchors)", () => {
    const up = edgeLabelAnchor(0, 0, 100, 0, 1, 0.4);
    const down = edgeLabelAnchor(0, 0, 100, 0, 1, -0.4);
    expect(up.y).not.toBeCloseTo(down.y);
  });

  it("guards coincident endpoints (no NaN)", () => {
    const a = edgeLabelAnchor(10, 10, 10, 10, 1, 0.4);
    expect(Number.isFinite(a.x)).toBe(true);
    expect(Number.isFinite(a.y)).toBe(true);
  });
});
