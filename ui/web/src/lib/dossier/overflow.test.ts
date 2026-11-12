import { describe, expect, it } from "vitest";

import { capList, expandToggleLabel } from "./overflow";

describe("capList", () => {
  const items = ["a", "b", "c", "d", "e"];

  it("returns the whole list untouched when within the cap", () => {
    const r = capList(items, 5, false);
    expect(r.shown).toEqual(items);
    expect(r.hidden).toBe(0);
    expect(r.hasMore).toBe(false);
  });

  it("caps to the head and reports the hidden count when collapsed", () => {
    const r = capList(items, 2, false);
    expect(r.shown).toEqual(["a", "b"]);
    expect(r.hidden).toBe(3);
    expect(r.hasMore).toBe(true);
  });

  it("shows everything but still flags hasMore when expanded", () => {
    const r = capList(items, 2, true);
    expect(r.shown).toEqual(items);
    expect(r.hidden).toBe(0);
    expect(r.hasMore).toBe(true);
  });

  it("does not mutate the input", () => {
    const copy = [...items];
    capList(items, 2, false);
    expect(items).toEqual(copy);
  });

  it("treats a non-positive cap as zero while still offering a toggle", () => {
    const r = capList(items, 0, false);
    expect(r.shown).toEqual([]);
    expect(r.hidden).toBe(5);
    expect(r.hasMore).toBe(true);
  });

  it("handles an empty list without offering a toggle", () => {
    const r = capList<string>([], 3, false);
    expect(r.shown).toEqual([]);
    expect(r.hidden).toBe(0);
    expect(r.hasMore).toBe(false);
  });
});

describe("expandToggleLabel", () => {
  it("groups thousands when collapsed", () => {
    expect(expandToggleLabel(2058, false)).toBe("Show all 2,058");
  });

  it("reads 'Show fewer' when expanded", () => {
    expect(expandToggleLabel(2058, true)).toBe("Show fewer");
  });
});
