import { describe, expect, it } from "vitest";

import {
  edgeColor,
  edgeLegendForSlice,
  getGraphTheme,
  isAdcsEdgeKind,
  isInferredEdge,
  kindColor,
  nodeColor,
} from "./encoding";

describe("getGraphTheme", () => {
  it("flips the label halo opposite the text in each theme (the critical fix)", () => {
    // Dark: near-white text needs a black halo; light: near-black text needs white.
    expect(getGraphTheme("dark").labelHalo.toLowerCase()).toBe("#08080a");
    expect(getGraphTheme("light").labelHalo.toLowerCase()).toBe("#ffffff");
  });

  it("uses a deep attack-path cyan on light (bright cyan is invisible on white)", () => {
    expect(getGraphTheme("dark").pathEdge).toBe("#38e0ff");
    expect(getGraphTheme("light").pathEdge).toBe("#0891b2");
  });

  it("keeps geometry (edge/path sizes) theme-independent", () => {
    const d = getGraphTheme("dark");
    const l = getGraphTheme("light");
    expect(d.edgeSize).toBe(l.edgeSize);
    expect(d.pathEdgeSize).toBe(l.pathEdgeSize);
  });
});

describe("kindColor / nodeColor", () => {
  it("selects the per-theme palette", () => {
    expect(kindColor("User", "dark")).toBe("#5aa9ff");
    expect(kindColor("User", "light")).toBe("#2563eb");
  });

  it("falls back to the theme default for an unknown kind", () => {
    expect(kindColor("Nope", "dark")).toBe(getGraphTheme("dark").defaultColor);
    expect(kindColor("Nope", "light")).toBe(getGraphTheme("light").defaultColor);
  });

  it("forces Tier-0 red over the kind color, per theme", () => {
    expect(nodeColor({ kind: "User", highvalue: true }, "dark")).toBe("#ff5d5d");
    expect(nodeColor({ kind: "User", highvalue: true }, "light")).toBe("#dc2626");
    expect(nodeColor({ kind: "User", highvalue: false }, "light")).toBe("#2563eb");
  });
});

describe("AD CS edge styling", () => {
  it("recognises the AD CS / PKI edge family (topology + enrollment + ESC)", () => {
    expect(isAdcsEdgeKind("PublishedTo")).toBe(true);
    expect(isAdcsEdgeKind("Enroll")).toBe(true);
    expect(isAdcsEdgeKind("ADCSESC1")).toBe(true);
    expect(isAdcsEdgeKind("GoldenCert")).toBe(true);
    expect(isAdcsEdgeKind("WraithESC4TemplateControl")).toBe(true);
    // non-AD CS kinds are not in the family
    expect(isAdcsEdgeKind("MemberOf")).toBe(false);
    expect(isAdcsEdgeKind("GenericAll")).toBe(false);
  });

  it("drives the inferred shade off confidence, not a per-kind list", () => {
    expect(isInferredEdge("inferred")).toBe(true);
    expect(isInferredEdge("confirmed")).toBe(false);
    expect(isInferredEdge(null)).toBe(false);
    expect(isInferredEdge(undefined)).toBe(false);
  });

  it("paints confirmed AD CS edges solid purple and inferred ESC the lighter shade", () => {
    const d = getGraphTheme("dark");
    const l = getGraphTheme("light");
    // confirmed topology → adcsEdge; inferred composite → adcsEdgeInferred (per theme)
    expect(edgeColor("PublishedTo", "confirmed", "dark")).toBe(d.adcsEdge);
    expect(edgeColor("ADCSESC1", "inferred", "dark")).toBe(d.adcsEdgeInferred);
    expect(edgeColor("PublishedTo", "confirmed", "light")).toBe(l.adcsEdge);
    expect(edgeColor("ADCSESC1", "inferred", "light")).toBe(l.adcsEdgeInferred);
    // the confirmed and inferred shades differ (visually honest) in both themes
    expect(d.adcsEdge).not.toBe(d.adcsEdgeInferred);
    expect(l.adcsEdge).not.toBe(l.adcsEdgeInferred);
  });

  it("leaves every non-AD CS edge on the calm base tone (graph stays minimal)", () => {
    expect(edgeColor("MemberOf", "confirmed", "dark")).toBe(getGraphTheme("dark").edge);
    expect(edgeColor("GenericAll", null, "light")).toBe(getGraphTheme("light").edge);
  });

  it("builds the AD CS relationship legend only from edges actually present", () => {
    expect(edgeLegendForSlice([], "dark")).toEqual([]);
    expect(edgeLegendForSlice([{ kind: "MemberOf", confidence: "confirmed" }], "dark")).toEqual([]);
    const both = edgeLegendForSlice(
      [
        { kind: "PublishedTo", confidence: "confirmed" },
        { kind: "ADCSESC1", confidence: "inferred" },
      ],
      "dark",
    );
    expect(both.map((e) => e.inferred)).toEqual([false, true]); // confirmed leads inferred
    expect(both[1].label).toMatch(/inferred/i);
  });
});
