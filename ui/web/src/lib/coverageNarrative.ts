/**
 * Plain-language coverage verdict (design doc 17 §5) — a PURE, deterministic
 * render of the existing `CoverageReport`. No backend call, no new logic: it
 * reuses the backend's capability statuses + verbatim reason notes, iterating
 * `capabilities` in the array order the backend already fixed (declared catalog
 * order) so identical reports produce identical text.
 *
 * Reserved-but-uploaded artifacts (gap_class `reserved_pass_not_wired:<id>`) are
 * worded from their note ("stored for provenance; pass not wired") — never "you
 * did not provide" (the operator DID provide them).
 */

import { KIND_LABELS, type ArtifactKindId, type CoverageReport } from "@/lib/api";

const RESERVED_PREFIX = "reserved_pass_not_wired:";

function kindLabel(id: string): string {
  return KIND_LABELS[id as ArtifactKindId] ?? id;
}

/** Join labels as "A", "A and B", "A, B and C". */
function humanJoin(items: string[]): string {
  if (items.length === 0) return "";
  if (items.length === 1) return items[0];
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

export interface CoverageVerdict {
  present: string[];
  gains: string[];
  degraded: Array<{ label: string; note: string }>;
  losses: Array<{ label: string; note: string }>;
  unlockHints: string[];
  /** Whether anything at all can be produced (ntds present). */
  canAnalyze: boolean;
}

/** Structured verdict for the banner (pure; declared-order deterministic).
 *
 * A reserved-but-uploaded capability keeps its honest note on its own loss/degraded
 * row (`<label> — <note>`, the "stored for provenance; pass not wired" wording) and
 * is NOT also emitted as a separate sentence — the note prints exactly once. Its
 * artifact is excluded from the unlock hints (the operator already provided it). */
export function coverageVerdict(report: CoverageReport): CoverageVerdict {
  const present = report.present_kinds.map(kindLabel);
  const gains: string[] = [];
  const degraded: Array<{ label: string; note: string }> = [];
  const losses: Array<{ label: string; note: string }> = [];
  const unlockSeen = new Set<string>();
  const unlockHints: string[] = [];

  for (const cap of report.capabilities) {
    if (cap.status === "available") {
      gains.push(cap.label);
      continue;
    }
    const note = cap.reasons[0]?.note ?? "";
    if (cap.status === "degraded") degraded.push({ label: cap.label, note });
    else losses.push({ label: cap.label, note });

    for (const r of cap.reasons) {
      if (r.gap_class.startsWith(RESERVED_PREFIX)) continue; // provided; not an unlock hint
      const label = kindLabel(r.missing_artifact_id);
      if (!unlockSeen.has(r.missing_artifact_id)) {
        unlockSeen.add(r.missing_artifact_id);
        unlockHints.push(label);
      }
    }
  }

  return { present, gains, degraded, losses, unlockHints, canAnalyze: report.can_analyze };
}

/**
 * The full deterministic verdict sentence block (testable without the DOM).
 * Omits empty clauses; identical reports → identical string.
 */
export function coverageNarrative(report: CoverageReport): string {
  const v = coverageVerdict(report);
  const parts: string[] = [];

  if (v.present.length > 0 && v.gains.length > 0) {
    parts.push(`Because you provided ${humanJoin(v.present)}, you will get ${humanJoin(v.gains)}.`);
  } else if (v.present.length > 0) {
    parts.push(`You provided ${humanJoin(v.present)}.`);
  } else {
    parts.push("No artifacts provided yet — nothing can be produced until you add the NTDS database.");
  }

  if (v.losses.length > 0) {
    const clauses = v.losses.map((l) => `${l.label}${l.note ? ` — ${l.note}` : ""}`);
    parts.push(`You will NOT get: ${clauses.join("; ")}.`);
  }

  if (v.degraded.length > 0) {
    const clauses = v.degraded.map((d) => `${d.label}${d.note ? ` — ${d.note}` : ""}`);
    parts.push(`Partial: ${clauses.join("; ")}.`);
  }

  if (v.unlockHints.length > 0) {
    parts.push(`To unlock more, add: ${humanJoin(v.unlockHints)}.`);
  }

  return parts.join(" ");
}
