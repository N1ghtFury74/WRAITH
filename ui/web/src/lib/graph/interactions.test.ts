import { describe, expect, it } from "vitest";

import {
  isIncrementalLayout,
  jitter,
  SHOW_ALL_EDGE_CAP,
  shouldShowEdgeLabel,
  showAllEdgeLabelGate,
} from "./interactions";

describe("jitter", () => {
  it("is deterministic (same id → same offset)", () => {
    expect(jitter("ricksanchez")).toEqual(jitter("ricksanchez"));
    expect(jitter("node-abc-123")).toEqual(jitter("node-abc-123"));
  });

  it("produces a bounded, finite radius in [45, 90)", () => {
    for (const id of ["a", "", "Domain Admins", "S-1-5-21-1-2-3-512", "x".repeat(200)]) {
      const p = jitter(id);
      const r = Math.hypot(p.x, p.y);
      expect(Number.isFinite(p.x)).toBe(true);
      expect(Number.isFinite(p.y)).toBe(true);
      expect(r).toBeGreaterThanOrEqual(45 - 1e-9);
      expect(r).toBeLessThan(90);
    }
  });

  it("spreads different ids to different offsets (no stacking)", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i += 1) seen.add(JSON.stringify(jitter(`n${i}`)));
    // Not a strict guarantee, but 50 distinct ids should rarely collide.
    expect(seen.size).toBeGreaterThan(40);
  });
});

describe("isIncrementalLayout", () => {
  const base = {
    expandMode: true,
    variant: "graph" as const,
    useServer: false,
    prevCount: 90,
    nodeCount: 120,
    maxNodes: 2000,
  };

  it("is true for a genuine walk expansion", () => {
    expect(isIncrementalLayout(base)).toBe(true);
  });

  it("is false when the page did not flag an expansion (e.g. a filter change)", () => {
    // THE bug this guards: a superset produced by a filter must re-layout fresh.
    expect(isIncrementalLayout({ ...base, expandMode: false })).toBe(false);
  });

  it("is false for the first render (no remembered positions)", () => {
    expect(isIncrementalLayout({ ...base, prevCount: 0 })).toBe(false);
  });

  it("is false for path views and server-laid slices", () => {
    expect(isIncrementalLayout({ ...base, variant: "path" })).toBe(false);
    expect(isIncrementalLayout({ ...base, useServer: true })).toBe(false);
  });

  it("is false over the client layout cap and for an empty slice", () => {
    expect(isIncrementalLayout({ ...base, nodeCount: 2001 })).toBe(false);
    expect(isIncrementalLayout({ ...base, nodeCount: 0 })).toBe(false);
  });
});

describe("shouldShowEdgeLabel", () => {
  const off = {
    isolating: false,
    isolatedOn: false,
    focusActive: false,
    focusedOn: false,
    isPath: false,
    showAll: false,
  };

  it("hides every edge label in the clean default view", () => {
    expect(shouldShowEdgeLabel(off)).toBe(false);
  });

  it("labels only the isolated path's edges when isolating", () => {
    expect(shouldShowEdgeLabel({ ...off, isolating: true, isolatedOn: true })).toBe(true);
    expect(shouldShowEdgeLabel({ ...off, isolating: true, isolatedOn: false })).toBe(false);
    // isolation wins over showAll/focus
    expect(
      shouldShowEdgeLabel({ ...off, isolating: true, isolatedOn: false, showAll: true, focusActive: true, focusedOn: true }),
    ).toBe(false);
  });

  it("labels only the focused node's incident edges when focusing", () => {
    expect(shouldShowEdgeLabel({ ...off, focusActive: true, focusedOn: true })).toBe(true);
    expect(shouldShowEdgeLabel({ ...off, focusActive: true, focusedOn: false })).toBe(false);
    // focus wins over showAll for non-incident edges
    expect(shouldShowEdgeLabel({ ...off, focusActive: true, focusedOn: false, showAll: true })).toBe(false);
  });

  it("labels all edges in a path view or when 'show all' is on", () => {
    expect(shouldShowEdgeLabel({ ...off, isPath: true })).toBe(true);
    expect(shouldShowEdgeLabel({ ...off, showAll: true })).toBe(true);
  });
});

describe("showAllEdgeLabelGate", () => {
  it("allows labelling all edges at or below the cap (no reason)", () => {
    expect(showAllEdgeLabelGate(0)).toEqual({ allowed: true, reason: null });
    expect(showAllEdgeLabelGate(SHOW_ALL_EDGE_CAP)).toEqual({ allowed: true, reason: null });
  });

  it("falls back to focus-only past the cap, with an honest reason", () => {
    const gate = showAllEdgeLabelGate(SHOW_ALL_EDGE_CAP + 1);
    expect(gate.allowed).toBe(false);
    expect(gate.reason).toContain(String(SHOW_ALL_EDGE_CAP + 1));
  });

  it("honours a custom cap", () => {
    expect(showAllEdgeLabelGate(11, 10).allowed).toBe(false);
    expect(showAllEdgeLabelGate(10, 10).allowed).toBe(true);
  });
});
