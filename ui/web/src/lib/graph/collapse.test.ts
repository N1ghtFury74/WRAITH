import { describe, expect, it } from "vitest";

import type { GraphSlice } from "@/lib/api";

import { applyCollapse, removableNodeIds, type WalkStep } from "./collapse";

function node(id: string) {
  return { node_id: id, kind: "User", label: id, object_sid: null, tier: null, highvalue: false, x: null, y: null };
}
function edge(id: string, s: string, t: string) {
  return { edge_id: id, kind: "MemberOf", source: s, target: t, confidence: null, is_inherited: null };
}

const steps: WalkStep[] = [
  { seedId: "seed", introduced: ["a", "b"] },
  { seedId: "a", introduced: ["c", "b"] }, // b shared with step 0
];

describe("removableNodeIds", () => {
  it("removes only the step's UNIQUELY-introduced nodes (not shared, not base)", () => {
    // dropping step 1: c is unique to it; b is shared with step 0 → keep; a is a base/seed node.
    const removable = removableNodeIds(steps, 1, ["seed"]);
    expect([...removable].sort()).toEqual(["c"]);
  });

  it("never removes base nodes", () => {
    const removable = removableNodeIds([{ seedId: "x", introduced: ["base1", "n"] }], 0, ["base1"]);
    expect([...removable].sort()).toEqual(["n"]);
  });

  it("returns empty for an out-of-range index", () => {
    expect(removableNodeIds(steps, 5, []).size).toBe(0);
  });
});

describe("applyCollapse", () => {
  const slice: GraphSlice = {
    nodes: [node("seed"), node("a"), node("b"), node("c")],
    edges: [edge("e1", "seed", "a"), edge("e2", "a", "c"), edge("e3", "seed", "b")],
    total_matched: 4,
    returned: 4,
    truncated: false,
    layout: "none",
    seed_node_ids: [],
    depth: 0,
  };

  it("drops removed nodes and any edge that loses an endpoint", () => {
    const next = applyCollapse(slice, new Set(["c"]));
    expect(next.nodes.map((n) => n.node_id).sort()).toEqual(["a", "b", "seed"]);
    // e2 (a->c) is dropped because c is gone.
    expect(next.edges.map((e) => e.edge_id).sort()).toEqual(["e1", "e3"]);
    expect(next.total_matched).toBe(3);
    expect(next.returned).toBe(3);
  });

  it("returns the same slice when nothing is removable", () => {
    expect(applyCollapse(slice, new Set())).toBe(slice);
  });
});
