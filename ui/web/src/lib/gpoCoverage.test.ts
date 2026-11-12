import { describe, expect, it } from "vitest";

import {
  COV_ADMIN_TO_EDGES,
  COV_FOLDERS_MATCHED,
  COV_LOCAL_GROUP_EDGES,
  COV_PRIVILEGE_EDGES,
  gpoHeadline,
  SKIP_FILE_OVERSIZE,
  SKIP_FILE_READ_ERROR,
  SKIP_GPP_CPASSWORD_FINDING,
  SKIP_GPP_PARSE_ERROR,
  SKIP_INF_PARSE_ERROR,
  SKIP_MEMBER_NAME_UNRESOLVED,
  SKIP_ORPHAN_FOLDER,
  SKIP_PREG_PARSE_ERROR,
  SKIP_SCOPE_COMPUTER_UNRESOLVED,
  SKIP_SYSVOL_MISSING,
  summarizeGpoCoverage,
} from "./gpoCoverage";

describe("gpoHeadline", () => {
  it("reads every missing coverage key as 0 (engine omits zero-count keys)", () => {
    expect(gpoHeadline({})).toEqual({
      gposProcessed: 0,
      inferredEdges: 0,
      adminToEdges: 0,
      localGroupEdges: 0,
      privilegeEdges: 0,
    });
  });

  it("sums inferredEdges client-side from local-group + privilege, never AdminTo", () => {
    const h = gpoHeadline({
      [COV_FOLDERS_MATCHED]: 3,
      [COV_ADMIN_TO_EDGES]: 7,
      [COV_LOCAL_GROUP_EDGES]: 5,
      [COV_PRIVILEGE_EDGES]: 4,
    });
    expect(h.gposProcessed).toBe(3);
    // inferred edges = local_group + privilege only (AdminTo is NOT folded in here)
    expect(h.inferredEdges).toBe(9);
    expect(h.adminToEdges).toBe(7);
    expect(h.localGroupEdges).toBe(5);
    expect(h.privilegeEdges).toBe(4);
  });

  it("never treats a negative stray count as a real figure", () => {
    const h = gpoHeadline({ [COV_LOCAL_GROUP_EDGES]: -2, [COV_PRIVILEGE_EDGES]: 3 });
    expect(h.localGroupEdges).toBe(0);
    expect(h.inferredEdges).toBe(3);
  });
});

describe("summarizeGpoCoverage", () => {
  it("returns no rows when nothing GPO was skipped", () => {
    expect(summarizeGpoCoverage({})).toEqual([]);
    expect(
      summarizeGpoCoverage({
        [SKIP_SYSVOL_MISSING]: 0,
        [SKIP_ORPHAN_FOLDER]: 0,
        [SKIP_GPP_CPASSWORD_FINDING]: 0,
      }),
    ).toEqual([]);
  });

  it("surfaces missing SYSVOL as a degraded gap, framed as 'files missing, not empty'", () => {
    const rows = summarizeGpoCoverage({ [SKIP_SYSVOL_MISSING]: 2 });
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe(SKIP_SYSVOL_MISSING);
    expect(rows[0].tone).toBe("degraded");
    expect(rows[0].count).toBe(2);
    expect(rows[0].note).toMatch(/NOT because the GPO is empty/i);
  });

  it("treats orphan folders and unresolved members as muted, honestly-counted skips", () => {
    const rows = summarizeGpoCoverage({
      [SKIP_ORPHAN_FOLDER]: 1,
      [SKIP_MEMBER_NAME_UNRESOLVED]: 4,
    });
    expect(rows.map((r) => r.id)).toEqual([SKIP_ORPHAN_FOLDER, SKIP_MEMBER_NAME_UNRESOLVED]);
    expect(rows.every((r) => r.tone === "muted")).toBe(true);
  });

  it("flags unresolved scope as degraded, never a silent drop", () => {
    const rows = summarizeGpoCoverage({ [SKIP_SCOPE_COMPUTER_UNRESOLVED]: 1 });
    expect(rows[0].tone).toBe("degraded");
    expect(rows[0].note).toMatch(/not dropped silently/i);
  });

  it("sums the three parse-error counters into one muted row", () => {
    const rows = summarizeGpoCoverage({
      [SKIP_INF_PARSE_ERROR]: 1,
      [SKIP_PREG_PARSE_ERROR]: 2,
      [SKIP_GPP_PARSE_ERROR]: 3,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe("gpo.parse_error");
    expect(rows[0].tone).toBe("muted");
    expect(rows[0].count).toBe(6);
  });

  it("sums read + oversize into one file-error row", () => {
    const rows = summarizeGpoCoverage({
      [SKIP_FILE_READ_ERROR]: 2,
      [SKIP_FILE_OVERSIZE]: 5,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe("gpo.file_error");
    expect(rows[0].count).toBe(7);
  });

  it("surfaces a GPP cpassword finding as degraded, pointing to the redacted finding store", () => {
    const rows = summarizeGpoCoverage({ [SKIP_GPP_CPASSWORD_FINDING]: 1 });
    expect(rows[0].id).toBe(SKIP_GPP_CPASSWORD_FINDING);
    expect(rows[0].tone).toBe("degraded");
    expect(rows[0].note).toMatch(/redacted/i);
  });

  it("is deterministic: missing/unresolved, then benign skips, then cpassword last", () => {
    const rows = summarizeGpoCoverage({
      [SKIP_GPP_CPASSWORD_FINDING]: 1,
      [SKIP_FILE_READ_ERROR]: 1,
      [SKIP_INF_PARSE_ERROR]: 1,
      [SKIP_MEMBER_NAME_UNRESOLVED]: 1,
      [SKIP_SCOPE_COMPUTER_UNRESOLVED]: 1,
      [SKIP_ORPHAN_FOLDER]: 1,
      [SKIP_SYSVOL_MISSING]: 1,
    });
    expect(rows.map((r) => r.id)).toEqual([
      SKIP_SYSVOL_MISSING,
      SKIP_ORPHAN_FOLDER,
      SKIP_SCOPE_COMPUTER_UNRESOLVED,
      SKIP_MEMBER_NAME_UNRESOLVED,
      "gpo.parse_error",
      "gpo.file_error",
      SKIP_GPP_CPASSWORD_FINDING,
    ]);
  });
});
