import { describe, expect, it } from "vitest";

import { DENSITY_ORDER, DENSITY_PX, normalizeDensity } from "./useDensity";

describe("normalizeDensity", () => {
  it("passes valid densities through", () => {
    expect(normalizeDensity("compact")).toBe("compact");
    expect(normalizeDensity("normal")).toBe("normal");
    expect(normalizeDensity("comfortable")).toBe("comfortable");
  });

  it("defaults anything invalid to normal (the shipped look)", () => {
    expect(normalizeDensity(undefined)).toBe("normal");
    expect(normalizeDensity(null)).toBe("normal");
    expect(normalizeDensity("huge")).toBe("normal");
    expect(normalizeDensity(14)).toBe("normal");
    expect(normalizeDensity("")).toBe("normal");
  });
});

describe("DENSITY_PX", () => {
  it("maps each stop to a distinct, monotonically increasing root size", () => {
    expect(DENSITY_PX.compact).toBe(14);
    expect(DENSITY_PX.normal).toBe(16);
    expect(DENSITY_PX.comfortable).toBe(18);
    expect(DENSITY_PX.compact).toBeLessThan(DENSITY_PX.normal);
    expect(DENSITY_PX.normal).toBeLessThan(DENSITY_PX.comfortable);
  });

  it("keeps normal at the browser-default 16px so the default preserves the shipped look", () => {
    expect(DENSITY_PX.normal).toBe(16);
  });
});

describe("DENSITY_ORDER", () => {
  it("runs small → large for the A− / A / A+ control", () => {
    expect([...DENSITY_ORDER]).toEqual(["compact", "normal", "comfortable"]);
  });

  it("is ordered by ascending root size", () => {
    const sizes = DENSITY_ORDER.map((d) => DENSITY_PX[d]);
    expect(sizes).toEqual([...sizes].sort((a, b) => a - b));
  });
});
