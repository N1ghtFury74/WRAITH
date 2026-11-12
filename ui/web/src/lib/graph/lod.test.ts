import { describe, expect, it } from "vitest";

import { DEFAULT_LOD, lodFor } from "./lod";

describe("lodFor", () => {
  it("reveals all node labels only when zoomed in close", () => {
    // Very close: every node label revealed.
    expect(lodFor(0.5)).toEqual({ edgeLabels: true, nodeLabels: true, nodeLabelsAll: true });
    // Default fit zoom (ratio 1): clean view — forced marks only, not all labels.
    expect(lodFor(1)).toEqual({ edgeLabels: true, nodeLabels: true, nodeLabelsAll: false });
  });

  it("drops edge labels first as the camera zooms out", () => {
    const mid = (DEFAULT_LOD.hideEdgeLabels + DEFAULT_LOD.hideNodeLabels) / 2;
    expect(lodFor(mid)).toEqual({ edgeLabels: false, nodeLabels: true, nodeLabelsAll: false });
  });

  it("drops node labels too when very zoomed out", () => {
    expect(lodFor(DEFAULT_LOD.hideNodeLabels + 1)).toEqual({
      edgeLabels: false,
      nodeLabels: false,
      nodeLabelsAll: false,
    });
  });

  it("is monotonic (zooming out only ever removes detail)", () => {
    let prevEdge = true;
    let prevNode = true;
    let prevAll = true;
    for (let r = 0.1; r <= 10; r += 0.1) {
      const s = lodFor(r);
      if (!prevEdge) expect(s.edgeLabels).toBe(false);
      if (!prevNode) expect(s.nodeLabels).toBe(false);
      if (!prevAll) expect(s.nodeLabelsAll).toBe(false);
      prevEdge = s.edgeLabels;
      prevNode = s.nodeLabels;
      prevAll = s.nodeLabelsAll;
    }
  });

  it("honours custom thresholds", () => {
    const t = { hideEdgeLabels: 1, hideNodeLabels: 2, showAllNodeLabels: 0.5 };
    expect(lodFor(1.5, t)).toEqual({ edgeLabels: false, nodeLabels: true, nodeLabelsAll: false });
    expect(lodFor(0.4, t)).toEqual({ edgeLabels: true, nodeLabels: true, nodeLabelsAll: true });
  });
});
