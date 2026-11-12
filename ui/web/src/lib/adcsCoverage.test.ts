import { describe, expect, it } from "vitest";

import {
  escDcDecidable,
  SKIP_CA_HOST_FACTS_ABSENT,
  SKIP_DC_CONFIG_ABSENT,
  SKIP_DC_CONFIG_HIVE_READ_ERROR,
  SKIP_DC_CONFIG_NO_HIVE,
  SKIP_ESC_FLAG_PARSE_ERROR,
  SKIP_ESC_TEMPLATE_UNRESOLVED,
  summarizeAdcsCoverage,
} from "./adcsCoverage";

describe("summarizeAdcsCoverage", () => {
  it("returns no rows when nothing AD CS was skipped", () => {
    expect(summarizeAdcsCoverage({})).toEqual([]);
    expect(
      summarizeAdcsCoverage({
        [SKIP_DC_CONFIG_ABSENT]: 0,
        [SKIP_DC_CONFIG_NO_HIVE]: 0,
        [SKIP_CA_HOST_FACTS_ABSENT]: 0,
      }),
    ).toEqual([]);
  });

  it("surfaces 'no DC SYSTEM hive' as undecidable, never safe", () => {
    // no hive => absent == no_hive (the whole undecidable count is the missing hive)
    const rows = summarizeAdcsCoverage({
      [SKIP_DC_CONFIG_ABSENT]: 2,
      [SKIP_DC_CONFIG_NO_HIVE]: 2,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe(SKIP_DC_CONFIG_NO_HIVE);
    expect(rows[0].status).toBe("undecidable");
    expect(rows[0].note).toMatch(/not a safe posture/i);
    // the value-unset plane must NOT fire (absent - no_hive == 0)
    expect(rows.some((r) => r.id === SKIP_DC_CONFIG_ABSENT)).toBe(false);
  });

  it("distinguishes 'hive present but value unset' from 'no hive'", () => {
    // hive read, both ESC9/10 values unset => absent > 0 while no_hive == 0
    const rows = summarizeAdcsCoverage({
      [SKIP_DC_CONFIG_ABSENT]: 3,
      [SKIP_DC_CONFIG_NO_HIVE]: 0,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe(SKIP_DC_CONFIG_ABSENT);
    expect(rows[0].status).toBe("undecidable");
    expect(rows[0].count).toBe(3);
    expect(rows[0].note).toMatch(/NOT 'clean'/i);
  });

  it("keeps the two DC-config planes separate when both fire", () => {
    // 1 branch had no hive, 2 more had the hive but a value unset => absent = 3
    const rows = summarizeAdcsCoverage({
      [SKIP_DC_CONFIG_ABSENT]: 3,
      [SKIP_DC_CONFIG_NO_HIVE]: 1,
    });
    const ids = rows.map((r) => r.id);
    expect(ids).toContain(SKIP_DC_CONFIG_NO_HIVE);
    expect(ids).toContain(SKIP_DC_CONFIG_ABSENT);
    expect(rows.find((r) => r.id === SKIP_DC_CONFIG_NO_HIVE)?.count).toBe(1);
    // value-unset subset = absent - no_hive = 2
    expect(rows.find((r) => r.id === SKIP_DC_CONFIG_ABSENT)?.count).toBe(2);
  });

  it("treats a hive read error as its own undecidable plane (not value-unset)", () => {
    const rows = summarizeAdcsCoverage({
      [SKIP_DC_CONFIG_ABSENT]: 1,
      [SKIP_DC_CONFIG_HIVE_READ_ERROR]: 1,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe(SKIP_DC_CONFIG_HIVE_READ_ERROR);
    // value-unset must be 0 (absent - no_hive - read_error == 0), so no absent row
    expect(rows.some((r) => r.id === SKIP_DC_CONFIG_ABSENT)).toBe(false);
  });

  it("does not own the CA-host plane (the dedicated CA-host card does)", () => {
    // ca_host_facts_absent is surfaced by caHostCoverage.ts, NOT here — so this
    // card stays the DC-SYSTEM-hive plane only and never double-reports it.
    expect(summarizeAdcsCoverage({ [SKIP_CA_HOST_FACTS_ABSENT]: 4 })).toEqual([]);
  });

  it("reports data-quality gaps distinctly from undecidable planes", () => {
    const rows = summarizeAdcsCoverage({
      [SKIP_ESC_TEMPLATE_UNRESOLVED]: 1,
      [SKIP_ESC_FLAG_PARSE_ERROR]: 2,
    });
    expect(rows.map((r) => r.status)).toEqual(["gap", "gap"]);
  });

  it("is deterministic in order: DC planes, then data-quality gaps", () => {
    const rows = summarizeAdcsCoverage({
      [SKIP_ESC_FLAG_PARSE_ERROR]: 1,
      [SKIP_CA_HOST_FACTS_ABSENT]: 1,
      [SKIP_DC_CONFIG_ABSENT]: 1,
      [SKIP_DC_CONFIG_NO_HIVE]: 1,
    });
    // CA-host plane is intentionally absent here (owned by caHostCoverage.ts).
    expect(rows.map((r) => r.id)).toEqual([SKIP_DC_CONFIG_NO_HIVE, SKIP_ESC_FLAG_PARSE_ERROR]);
  });
});

describe("escDcDecidable (never a false-safe)", () => {
  it("is false whenever the DC SYSTEM hive is absent, even with zero skips", () => {
    expect(escDcDecidable({}, false)).toBe(false);
    expect(escDcDecidable({ [SKIP_DC_CONFIG_ABSENT]: 0 }, false)).toBe(false);
  });

  it("is false when the hive is present but a branch was undecidable", () => {
    expect(escDcDecidable({ [SKIP_DC_CONFIG_ABSENT]: 1 }, true)).toBe(false);
    expect(escDcDecidable({ [SKIP_DC_CONFIG_HIVE_READ_ERROR]: 1 }, true)).toBe(false);
  });

  it("is true only when the hive is present and no branch was left undecidable", () => {
    expect(escDcDecidable({ [SKIP_DC_CONFIG_ABSENT]: 0 }, true)).toBe(true);
    expect(escDcDecidable({}, true)).toBe(true);
  });
});
