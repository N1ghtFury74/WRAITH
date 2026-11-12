import { describe, expect, it } from "vitest";

import type { GraphNode } from "@/lib/api";

import { filterSliceNodes, listSummary, orderSliceNodes } from "./list";

function node(partial: Partial<GraphNode> & Pick<GraphNode, "node_id">): GraphNode {
  return {
    node_id: partial.node_id,
    kind: partial.kind ?? "User",
    label: partial.label ?? partial.node_id,
    object_sid: partial.object_sid ?? null,
    tier: partial.tier ?? null,
    highvalue: partial.highvalue ?? false,
    x: partial.x ?? null,
    y: partial.y ?? null,
  };
}

describe("orderSliceNodes", () => {
  it("pins Tier-0 / high-value first, then kind, then label", () => {
    const nodes = [
      node({ node_id: "1", kind: "User", label: "zeta" }),
      node({ node_id: "2", kind: "Group", label: "admins", highvalue: true }),
      node({ node_id: "3", kind: "Computer", label: "alpha" }),
      node({ node_id: "4", kind: "User", label: "alpha" }),
    ];
    expect(orderSliceNodes(nodes).map((n) => n.node_id)).toEqual(["2", "3", "4", "1"]);
  });

  it("is case-insensitive on label and stable by node_id", () => {
    const nodes = [
      node({ node_id: "b", kind: "User", label: "Bravo" }),
      node({ node_id: "a", kind: "User", label: "bravo" }),
    ];
    expect(orderSliceNodes(nodes).map((n) => n.node_id)).toEqual(["a", "b"]);
  });

  it("does not mutate the input", () => {
    const nodes = [node({ node_id: "1" }), node({ node_id: "2", highvalue: true })];
    const before = nodes.map((n) => n.node_id);
    orderSliceNodes(nodes);
    expect(nodes.map((n) => n.node_id)).toEqual(before);
  });
});

describe("filterSliceNodes", () => {
  const nodes = [
    node({ node_id: "1", kind: "User", label: "Administrator" }),
    node({ node_id: "2", kind: "GPO", label: "Default Domain Policy" }),
  ];

  it("returns all when the term is blank", () => {
    expect(filterSliceNodes(nodes, "  ")).toHaveLength(2);
  });

  it("matches label or kind case-insensitively", () => {
    expect(filterSliceNodes(nodes, "admin").map((n) => n.node_id)).toEqual(["1"]);
    expect(filterSliceNodes(nodes, "gpo").map((n) => n.node_id)).toEqual(["2"]);
  });
});

describe("listSummary", () => {
  it("counts total + Tier-0 and carries the truncation flag", () => {
    const nodes = [
      node({ node_id: "1", highvalue: true }),
      node({ node_id: "2" }),
      node({ node_id: "3", highvalue: true }),
    ];
    expect(listSummary(nodes, true)).toEqual({ total: 3, tier0: 2, truncated: true });
  });
});
