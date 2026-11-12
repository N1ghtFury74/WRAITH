import { describe, expect, it } from "vitest";

import type { GraphEdge, GraphNode, GraphSlice } from "@/lib/api";

import { mergeSlices, newNodeCount, WALK_NODE_CAP } from "./merge";

function node(id: string, extra: Partial<GraphNode> = {}): GraphNode {
  return {
    node_id: id,
    kind: "User",
    label: id,
    object_sid: null,
    tier: null,
    highvalue: false,
    x: null,
    y: null,
    ...extra,
  };
}

function edge(id: string, source: string, target: string, kind = "MemberOf"): GraphEdge {
  return { edge_id: id, kind, source, target, confidence: "confirmed", is_inherited: false };
}

function slice(nodes: GraphNode[], edges: GraphEdge[], extra: Partial<GraphSlice> = {}): GraphSlice {
  return {
    nodes,
    edges,
    total_matched: nodes.length,
    returned: nodes.length,
    truncated: false,
    layout: "none",
    seed_node_ids: [],
    depth: 1,
    ...extra,
  };
}

describe("mergeSlices", () => {
  it("de-duplicates nodes by node_id and edges by edge_id", () => {
    const base = slice([node("a"), node("b")], [edge("e1", "a", "b")]);
    const add = slice([node("b"), node("c")], [edge("e1", "a", "b"), edge("e2", "b", "c")]);
    const out = mergeSlices(base, add);
    expect(out.nodes.map((n) => n.node_id).sort()).toEqual(["a", "b", "c"]);
    expect(out.edges.map((e) => e.edge_id).sort()).toEqual(["e1", "e2"]);
  });

  it("keeps base node attributes when an id is duplicated (first wins)", () => {
    const base = slice([node("a", { highvalue: true, label: "Domain Admins" })], []);
    const add = slice([node("a", { highvalue: false, label: "stale" })], []);
    const out = mergeSlices(base, add);
    expect(out.nodes).toHaveLength(1);
    expect(out.nodes[0].highvalue).toBe(true);
    expect(out.nodes[0].label).toBe("Domain Admins");
  });

  it("drops edges whose endpoints are not both present", () => {
    const base = slice([node("a"), node("b")], [edge("e1", "a", "b")]);
    // e2 points at "z" which is never added → must be dropped.
    const add = slice([node("c")], [edge("e2", "c", "z"), edge("e3", "a", "c")]);
    const out = mergeSlices(base, add);
    expect(out.edges.map((e) => e.edge_id).sort()).toEqual(["e1", "e3"]);
  });

  it("recomputes totals, clears truncation, and marks client layout", () => {
    const base = slice([node("a")], [], { total_matched: 999, truncated: true, layout: "server" });
    const add = slice([node("b")], []);
    const out = mergeSlices(base, add);
    expect(out.total_matched).toBe(2);
    expect(out.returned).toBe(2);
    expect(out.truncated).toBe(false);
    expect(out.layout).toBe("none");
  });

  it("preserves base-only slice fields (seed/depth)", () => {
    const base = slice([node("a")], [], { seed_node_ids: ["a"], depth: 3 });
    const out = mergeSlices(base, slice([node("b")], []));
    expect(out.seed_node_ids).toEqual(["a"]);
    expect(out.depth).toBe(3);
  });

  it("does not mutate its inputs", () => {
    const base = slice([node("a")], [edge("e1", "a", "a")]);
    const add = slice([node("b")], []);
    mergeSlices(base, add);
    expect(base.nodes).toHaveLength(1);
    expect(add.nodes).toHaveLength(1);
  });
});

describe("newNodeCount", () => {
  it("counts only nodes not already in base", () => {
    const base = slice([node("a"), node("b")], []);
    expect(newNodeCount(base, slice([node("b"), node("c"), node("d")], []))).toBe(2);
    expect(newNodeCount(base, slice([node("a"), node("b")], []))).toBe(0);
    expect(newNodeCount(base, slice([], []))).toBe(0);
  });
});

describe("WALK_NODE_CAP", () => {
  it("is a sane positive bound", () => {
    expect(WALK_NODE_CAP).toBeGreaterThan(50);
    expect(WALK_NODE_CAP).toBeLessThanOrEqual(2000);
  });
});
