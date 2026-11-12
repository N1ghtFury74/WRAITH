import { describe, expect, it } from "vitest";

import type { ConnectorResult } from "@/lib/api";

import { classifyConnectorLane, connectorUnionSlice, laneRank, viaNodeSet } from "./connector";

describe("classifyConnectorLane", () => {
  it("is control when no structural hop is present", () => {
    expect(classifyConnectorLane(["MemberOf", "GenericAll"], "User", "GPO")).toBe("control");
  });

  it("is scope for a GPO → … → principal structural chain", () => {
    expect(classifyConnectorLane(["GPLink", "Contains"], "GPO", "User")).toBe("scope");
    expect(classifyConnectorLane(["GPLink", "Contains"], "GPO", "Computer")).toBe("scope");
  });

  it("is noise for pure containment / co-location", () => {
    // OU → OU containment
    expect(classifyConnectorLane(["Contains", "Contains"], "OU", "OU")).toBe("noise");
    // Domain contains a principal (structural start that is not a GPO)
    expect(classifyConnectorLane(["Contains"], "Domain", "User")).toBe("noise");
  });
});

describe("laneRank", () => {
  it("ranks control before scope", () => {
    expect(laneRank("control")).toBeLessThan(laneRank("scope"));
  });
});

function result(partial: Partial<ConnectorResult>): ConnectorResult {
  return {
    paths: [],
    control_count: 0,
    scope_count: 0,
    retained_node_ids: [],
    via_node_ids: [],
    truncated: false,
    max_hops: 6,
    caveats: [],
    counted_gaps: {},
    note: null,
    ...partial,
  };
}

describe("connectorUnionSlice + viaNodeSet", () => {
  const r = result({
    retained_node_ids: ["u", "g"],
    via_node_ids: ["ou"],
    control_count: 0,
    scope_count: 1,
    paths: [
      {
        lane: "scope",
        length: 2,
        confidence: "confirmed",
        source_node_id: "g",
        target_node_id: "u",
        caveat: "rsop",
        nodes: [
          { node_id: "g", kind: "GPO", label: "GPO1" },
          { node_id: "ou", kind: "OU", label: "OU=WS" },
          { node_id: "u", kind: "User", label: "alice" },
        ],
        edges: [
          { source: "g", target: "ou", kind: "GPLink", edge_id: "e1" },
          { source: "ou", target: "u", kind: "Contains", edge_id: "e2" },
        ],
      },
    ],
  });

  it("unions all chain nodes + hops, deduped", () => {
    const slice = connectorUnionSlice(r);
    expect(slice.nodes.map((n) => n.node_id).sort()).toEqual(["g", "ou", "u"]);
    expect(slice.edges.map((e) => e.edge_id).sort()).toEqual(["e1", "e2"]);
    expect(slice.layout).toBe("none");
  });

  it("exposes the via-node set (intermediates added to connect)", () => {
    expect([...viaNodeSet(r)]).toEqual(["ou"]);
  });
});
