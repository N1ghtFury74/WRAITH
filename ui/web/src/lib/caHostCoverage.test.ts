import { describe, expect, it } from "vitest";

import {
  COV_CA_NODE_FINDINGS,
  COV_ESC6A,
  COV_MANAGE_CA,
  COV_MANAGE_CERTIFICATES,
  SKIP_CA_GRANTEE_UNRESOLVED,
  SKIP_CA_HOST_CORRELATION_AMBIGUOUS,
  SKIP_CA_HOST_FACTS_ABSENT,
  SKIP_CA_HOST_HIVE_READ,
  SKIP_CA_HOST_NAME_MISMATCH,
  SKIP_CA_SECURITY_ABSENT,
  SKIP_DCOM_ABSENT,
  summarizeCaHostCoverage,
} from "./caHostCoverage";

describe("summarizeCaHostCoverage", () => {
  it("is not relevant on a domain with no CA host signal at all", () => {
    const c = summarizeCaHostCoverage({}, {}, false);
    expect(c.relevant).toBe(false);
    expect(c.state).toBe("undecidable");
  });

  it("WITHOUT the hive: CA-role/ESC are undecidable counted gaps, not clean", () => {
    const c = summarizeCaHostCoverage({}, { [SKIP_CA_HOST_FACTS_ABSENT]: 4 }, false);
    expect(c.relevant).toBe(true);
    expect(c.state).toBe("undecidable");
    expect(c.hivePresent).toBe(false);
    expect(c.factsAbsent).toBe(4);
    expect(c.decidedTotal).toBe(0);
  });

  it("WITH the hive and nothing blocked: decidable, with decided emissions summed", () => {
    const c = summarizeCaHostCoverage(
      {
        [COV_MANAGE_CA]: 2,
        [COV_MANAGE_CERTIFICATES]: 1,
        [COV_ESC6A]: 3,
        [COV_CA_NODE_FINDINGS]: 2,
      },
      {},
      true,
    );
    expect(c.state).toBe("decidable");
    expect(c.decidedTotal).toBe(8);
    expect(c.nodeFindings).toBe(2);
  });

  it("never reads a mis-correlated hive as clean (present but name mismatch)", () => {
    const c = summarizeCaHostCoverage({}, { [SKIP_CA_HOST_NAME_MISMATCH]: 1 }, true);
    expect(c.state).toBe("undecidable");
    expect(c.gaps.some((g) => g.id === SKIP_CA_HOST_NAME_MISMATCH)).toBe(true);
  });

  it("never reads an unreadable hive as clean (present but hive read error)", () => {
    const c = summarizeCaHostCoverage({}, { [SKIP_CA_HOST_HIVE_READ]: 1 }, true);
    expect(c.state).toBe("undecidable");
    expect(c.gaps[0].tone).toBe("undecidable");
  });

  it("tracks the SOFTWARE/DCOM split independently of the SYSTEM facts", () => {
    // SYSTEM present & decided, but SOFTWARE absent → DCOM undecidable, still decidable overall.
    const c = summarizeCaHostCoverage(
      { [COV_MANAGE_CA]: 1 },
      { [SKIP_DCOM_ABSENT]: 1 },
      true,
    );
    expect(c.state).toBe("decidable");
    expect(c.dcomAbsent).toBe(1);
  });

  it("orders gaps: undecidable blockers before benign decode skips", () => {
    const c = summarizeCaHostCoverage(
      {},
      {
        [SKIP_CA_GRANTEE_UNRESOLVED]: 2,
        [SKIP_CA_HOST_HIVE_READ]: 1,
        [SKIP_CA_SECURITY_ABSENT]: 1,
        [SKIP_CA_HOST_CORRELATION_AMBIGUOUS]: 1,
      },
      true,
    );
    const tones = c.gaps.map((g) => g.tone);
    // every "undecidable" must come before any "muted"
    const firstMuted = tones.indexOf("muted");
    const lastUndecidable = tones.lastIndexOf("undecidable");
    expect(firstMuted === -1 || lastUndecidable < firstMuted).toBe(true);
  });

  it("ignores zero-valued keys (engine omits them, but defensively)", () => {
    const c = summarizeCaHostCoverage(
      { [COV_MANAGE_CA]: 0 },
      { [SKIP_CA_HOST_FACTS_ABSENT]: 0 },
      false,
    );
    expect(c.relevant).toBe(false);
    expect(c.gaps).toHaveLength(0);
  });
});
