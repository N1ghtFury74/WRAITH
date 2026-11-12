import { describe, expect, it } from "vitest";

import { nextPref, normalizePref, resolveTheme } from "./useTheme";

describe("resolveTheme", () => {
  it("honours an explicit choice regardless of the OS signal", () => {
    expect(resolveTheme("light", true)).toBe("light");
    expect(resolveTheme("light", false)).toBe("light");
    expect(resolveTheme("dark", false)).toBe("dark");
    expect(resolveTheme("dark", true)).toBe("dark");
  });

  it("follows the OS signal in system mode", () => {
    expect(resolveTheme("system", true)).toBe("dark");
    expect(resolveTheme("system", false)).toBe("light");
  });
});

describe("normalizePref", () => {
  it("passes valid prefs through", () => {
    expect(normalizePref("light")).toBe("light");
    expect(normalizePref("dark")).toBe("dark");
    expect(normalizePref("system")).toBe("system");
  });

  it("defaults anything invalid to system", () => {
    expect(normalizePref(undefined)).toBe("system");
    expect(normalizePref(null)).toBe("system");
    expect(normalizePref("dim")).toBe("system");
    expect(normalizePref(42)).toBe("system");
  });
});

describe("nextPref", () => {
  it("cycles light → dark → system → light", () => {
    expect(nextPref("light")).toBe("dark");
    expect(nextPref("dark")).toBe("system");
    expect(nextPref("system")).toBe("light");
  });
});
