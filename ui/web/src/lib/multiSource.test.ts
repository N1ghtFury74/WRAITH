import { describe, expect, it } from "vitest";

import type { SourceCoverage, SourceInfo } from "@/lib/api";
import {
  aggregateCounts,
  crossDomainSignals,
  distinctDomains,
  distinctForests,
  hasLabelMismatch,
} from "@/lib/multiSource";

function cov(partial: Partial<SourceCoverage>): SourceCoverage {
  return {
    source_id: "s",
    dc_label: "DC",
    artifacts: [],
    coverage_counts: {},
    skip_counts: {},
    counted_gaps: {},
    ...partial,
  };
}

function src(partial: Partial<SourceInfo>): SourceInfo {
  return {
    source_id: "s",
    dc_label: "DC",
    domain_id: null,
    domain_fqdn: null,
    forest_id: "forest-1",
    declared_domain: null,
    is_global_catalog: null,
    node_count: 0,
    edge_count: 0,
    ...partial,
  };
}

describe("aggregateCounts", () => {
  it("sums coverage and skip across sources", () => {
    const agg = aggregateCounts([
      cov({ coverage_counts: { "edges.xd_trust": 2 }, skip_counts: { "edges.xd_gc_partial_replica": 1 } }),
      cov({ coverage_counts: { "edges.xd_trust": 3 }, skip_counts: { "edges.xd_gc_partial_replica": 4 } }),
    ]);
    expect(agg.coverage["edges.xd_trust"]).toBe(5);
    expect(agg.skip["edges.xd_gc_partial_replica"]).toBe(5);
  });

  it("is empty for no sources", () => {
    const agg = aggregateCounts([]);
    expect(agg.coverage).toEqual({});
    expect(agg.skip).toEqual({});
  });
});

describe("crossDomainSignals", () => {
  it("surfaces only measured keys — never a reassuring zero for an absent key", () => {
    const sig = crossDomainSignals({
      coverage: { "edges.xd_trust": 4, "edges.xd_fsp_resolved": 0 },
      skip: { "edges.xd_fsp_owning_domain_not_ingested": 2 },
    });
    expect(sig.found.map((r) => r.key)).toContain("edges.xd_trust");
    // Present-but-zero is still a measured fact → shown.
    expect(sig.found.map((r) => r.key)).toContain("edges.xd_fsp_resolved");
    // A gap key absent from the map must NOT appear (no fabricated 0).
    expect(sig.gaps.map((r) => r.key)).toEqual(["edges.xd_fsp_owning_domain_not_ingested"]);
    expect(sig.empty).toBe(false);
  });

  it("reports empty when nothing cross-domain was measured", () => {
    expect(crossDomainSignals({ coverage: {}, skip: {} }).empty).toBe(true);
  });

  it("pulls declaration mismatches out of skip counts", () => {
    const sig = crossDomainSignals({
      coverage: {},
      skip: { source_label_domain_mismatch: 1, "case_shape_mismatch:same_domain_two_dcs": 1 },
    });
    expect(sig.mismatches).toHaveLength(2);
  });
});

describe("domain / forest helpers", () => {
  it("dedups domains and forests", () => {
    const sources = [
      src({ domain_fqdn: "corp.example.com", forest_id: "f1" }),
      src({ domain_fqdn: "corp.example.com", forest_id: "f1" }),
      src({ domain_fqdn: "dev.example.com", forest_id: "f2" }),
    ];
    expect(distinctDomains(sources)).toEqual(["corp.example.com", "dev.example.com"]);
    expect(distinctForests(sources)).toEqual(["f1", "f2"]);
  });

  it("flags a label that disagrees with the derived fqdn (case-insensitive)", () => {
    expect(hasLabelMismatch(src({ declared_domain: "prod.local", domain_fqdn: "corp.local" }))).toBe(true);
    expect(hasLabelMismatch(src({ declared_domain: "CORP.local", domain_fqdn: "corp.local" }))).toBe(false);
    expect(hasLabelMismatch(src({ declared_domain: null, domain_fqdn: "corp.local" }))).toBe(false);
  });
});
