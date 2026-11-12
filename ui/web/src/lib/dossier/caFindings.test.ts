import { describe, expect, it } from "vitest";

import { CA_PROP_DCOM, CA_PROP_ESC11, CA_PROP_ESC16, caFindingDisplay } from "./caFindings";

describe("caFindingDisplay", () => {
  it("renders an ESC11 weak-posture flag as a risk-toned 'present' chip, not 'true'", () => {
    const d = caFindingDisplay({ prop: CA_PROP_ESC11, value: "true" });
    expect(d).toEqual({ badge: "present", tone: "risk" });
  });

  it("renders ESC16 the same way (risk 'present')", () => {
    expect(caFindingDisplay({ prop: CA_PROP_ESC16, value: "true" })).toEqual({
      badge: "present",
      tone: "risk",
    });
  });

  it("shows the DCOM summary verbatim as neutral context", () => {
    expect(caFindingDisplay({ prop: CA_PROP_DCOM, value: "EnableDCOM=Y" })).toEqual({
      badge: "EnableDCOM=Y",
      tone: "context",
    });
    expect(caFindingDisplay({ prop: CA_PROP_DCOM, value: "EnableDCOM=N" })).toEqual({
      badge: "EnableDCOM=N",
      tone: "context",
    });
  });

  it("is case/space-insensitive for the ESC boolean", () => {
    expect(caFindingDisplay({ prop: CA_PROP_ESC11, value: " TRUE " }).tone).toBe("risk");
  });

  it("degrades an unexpected ESC value to the raw value with neutral tone (never guessed)", () => {
    expect(caFindingDisplay({ prop: CA_PROP_ESC11, value: "false" })).toEqual({
      badge: "false",
      tone: "context",
    });
    expect(caFindingDisplay({ prop: CA_PROP_ESC16, value: "" })).toEqual({
      badge: "—",
      tone: "context",
    });
  });

  it("never emits an empty DCOM chip", () => {
    expect(caFindingDisplay({ prop: CA_PROP_DCOM, value: "" }).badge).toBe("DCOM");
  });
});
