import { describe, expect, it } from "vitest";

import type { DossierEdge } from "@/lib/api";

import { filterByLabel, groupInboundByController, kindBreakdown } from "./aces";

function edge(
  controllerId: string,
  label: string,
  kind: string,
  opts: { tier0?: boolean; ckind?: string } = {},
): DossierEdge {
  return {
    edge_id: `${controllerId}:${kind}`,
    kind,
    direction: "inbound",
    other: {
      node_id: controllerId,
      kind: opts.ckind ?? "User",
      label,
      is_tier0: opts.tier0 ?? false,
    },
    confidence: null,
    is_inherited: null,
    access_mask: null,
    object_type_guid: null,
    attribute_name: null,
  };
}

describe("groupInboundByController", () => {
  it("collapses many ACEs from one principal into a single group with sorted rights", () => {
    const edges = [
      edge("u1", "Alice", "WriteOwner"),
      edge("u1", "Alice", "GenericAll"),
      edge("u1", "Alice", "WriteDacl"),
    ];
    const groups = groupInboundByController(edges);
    expect(groups).toHaveLength(1);
    expect(groups[0].controller.node_id).toBe("u1");
    expect(groups[0].rights).toEqual(["GenericAll", "WriteDacl", "WriteOwner"]);
    expect(groups[0].edges).toHaveLength(3);
  });

  it("de-duplicates repeated right kinds in the rights chip list", () => {
    const groups = groupInboundByController([
      edge("u1", "Alice", "GenericAll"),
      edge("u1", "Alice", "GenericAll"),
    ]);
    expect(groups[0].rights).toEqual(["GenericAll"]);
    expect(groups[0].edges).toHaveLength(2); // raw rows preserved
  });

  it("orders Tier-0 controllers first, then by label", () => {
    const groups = groupInboundByController([
      edge("u3", "Zoe", "GenericAll"),
      edge("u2", "Bob", "GenericAll", { tier0: true }),
      edge("u1", "Amy", "GenericAll"),
    ]);
    expect(groups.map((g) => g.controller.label)).toEqual(["Bob", "Amy", "Zoe"]);
    expect(groups[0].isTier0).toBe(true);
  });

  it("returns an empty array for no edges", () => {
    expect(groupInboundByController([])).toEqual([]);
  });
});

describe("filterByLabel", () => {
  const items = [
    { label: "DC01", kind: "Computer" },
    { label: "Alice", kind: "User" },
    { label: "Domain Admins", kind: "Group" },
  ];

  it("returns all items for an empty/whitespace term", () => {
    expect(filterByLabel(items, "")).toHaveLength(3);
    expect(filterByLabel(items, "   ")).toHaveLength(3);
  });

  it("matches label substrings case-insensitively", () => {
    expect(filterByLabel(items, "dc").map((i) => i.label)).toEqual(["DC01"]);
    expect(filterByLabel(items, "ALICE").map((i) => i.label)).toEqual(["Alice"]);
  });

  it("also matches on kind", () => {
    expect(filterByLabel(items, "group").map((i) => i.label)).toEqual(["Domain Admins"]);
  });
});

describe("kindBreakdown", () => {
  it("counts by kind, ordered by count desc then kind asc", () => {
    const members = [
      { kind: "User" },
      { kind: "User" },
      { kind: "Computer" },
      { kind: "Group" },
      { kind: "Computer" },
      { kind: "User" },
    ];
    expect(kindBreakdown(members)).toEqual([
      { kind: "User", count: 3 },
      { kind: "Computer", count: 2 },
      { kind: "Group", count: 1 },
    ]);
  });

  it("is empty for no items", () => {
    expect(kindBreakdown([])).toEqual([]);
  });
});
