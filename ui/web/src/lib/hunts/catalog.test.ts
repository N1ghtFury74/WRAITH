import { describe, expect, it } from "vitest";

import type { PrebuiltQuery } from "@/lib/api";
import { CATEGORY_ORDER, groupQueries, huntMatches } from "@/lib/hunts/catalog";

/** Minimal catalog-query factory (only the fields the helpers read). */
function q(partial: Partial<PrebuiltQuery> & Pick<PrebuiltQuery, "id" | "category">): PrebuiltQuery {
  return {
    id: partial.id,
    label: partial.label ?? partial.id,
    description: partial.description ?? "",
    kind: partial.kind ?? "set",
    direction: partial.direction ?? "set",
    supported: partial.supported ?? true,
    reason: partial.reason ?? null,
    data_confidence: partial.data_confidence ?? "real",
    source_count: partial.source_count ?? null,
    category: partial.category,
  };
}

describe("groupQueries", () => {
  it("orders known categories by the fixed hunter order, not catalog order", () => {
    const queries = [
      q({ id: "a", category: "ADCS" }),
      q({ id: "b", category: "Privileged Access" }),
      q({ id: "c", category: "Delegation" }),
    ];
    const groups = groupQueries(queries, "");
    expect(groups.map(([c]) => c)).toEqual(["Privileged Access", "Delegation", "ADCS"]);
  });

  it("trails unknown categories alphabetically after the known ones", () => {
    const queries = [
      q({ id: "z", category: "Zeta" }),
      q({ id: "m", category: "Alpha" }),
      q({ id: "p", category: "Privileged Access" }),
    ];
    const groups = groupQueries(queries, "");
    expect(groups.map(([c]) => c)).toEqual(["Privileged Access", "Alpha", "Zeta"]);
  });

  it("preserves catalog (server) order of hunts within a category", () => {
    const queries = [
      q({ id: "second", category: "Topology" }),
      q({ id: "first", category: "Topology" }),
    ];
    const [[, items]] = groupQueries(queries, "");
    expect(items.map((x) => x.id)).toEqual(["second", "first"]);
  });

  it("filters hunts by term and drops emptied categories", () => {
    const queries = [
      q({ id: "da", category: "Privileged Access", label: "Domain Admins" }),
      q({ id: "trust", category: "Topology", label: "Forest Trusts" }),
    ];
    const groups = groupQueries(queries, "trust");
    expect(groups.map(([c]) => c)).toEqual(["Topology"]);
    expect(groups[0][1].map((x) => x.id)).toEqual(["trust"]);
  });

  it("matches on description and category as well as label, case-insensitively", () => {
    const queries = [
      q({ id: "x", category: "Delegation", label: "RBCD", description: "resource-based constrained" }),
      q({ id: "y", category: "Stale/Risk", label: "Kerberoastable" }),
    ];
    expect(groupQueries(queries, "CONSTRAINED").map(([, i]) => i[0].id)).toEqual(["x"]);
    expect(groupQueries(queries, "delegation").map(([, i]) => i[0].id)).toEqual(["x"]);
  });

  it("handles undefined / empty input without throwing", () => {
    expect(groupQueries(undefined, "")).toEqual([]);
    expect(groupQueries([], "anything")).toEqual([]);
  });

  it("is deterministic across repeated calls", () => {
    const queries = [
      q({ id: "b", category: "Gamma" }),
      q({ id: "a", category: "Beta" }),
      q({ id: "p", category: "ADCS" }),
    ];
    expect(groupQueries(queries, "")).toEqual(groupQueries(queries, ""));
  });
});

describe("huntMatches", () => {
  const item = q({ id: "h", category: "Dangerous ACLs", label: "GenericAll", description: "write DACL" });

  it("matches everything on an empty term", () => {
    expect(huntMatches(item, "")).toBe(true);
  });

  it("matches label, description, and category substrings", () => {
    expect(huntMatches(item, "genericall")).toBe(true);
    expect(huntMatches(item, "dacl")).toBe(true);
    expect(huntMatches(item, "dangerous")).toBe(true);
  });

  it("returns false when nothing contains the term", () => {
    expect(huntMatches(item, "kerberoast")).toBe(false);
  });
});

describe("CATEGORY_ORDER", () => {
  it("has no duplicate categories", () => {
    expect(new Set(CATEGORY_ORDER).size).toBe(CATEGORY_ORDER.length);
  });
});
