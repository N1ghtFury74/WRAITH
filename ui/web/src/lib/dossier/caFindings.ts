/**
 * Pure presentation helper for CA-host NODE-LEVEL dossier findings (module 35b).
 *
 * The API returns each finding self-describing (title + caption + a NON-SECRET
 * `value`); this maps the raw `value` to a legible chip + tone without ever
 * inventing an abuse. ESC11/ESC16 are boolean weak-posture flags (`value === "true"`
 * means the weak condition HOLDS — a risk), so a bare "true" chip would read badly;
 * the DCOM summary is context (`EnableDCOM=Y/N`) and is shown verbatim. No React.
 */

import type { CaNodeFindingOut } from "@/lib/api";

/** The closed set of finding props the gated engine emits (mirrors adcs_esc.py). */
export const CA_PROP_ESC11 = "esc11_no_encrypt_enforcement";
export const CA_PROP_ESC16 = "esc16_sid_ext_disabled";
export const CA_PROP_DCOM = "dcom_restrictions";

/** Chip text + tone for one finding's decided value. */
export interface CaFindingDisplay {
  /** Short chip text for the decided value (never a secret). */
  badge: string;
  /** `risk` = an ESC weak-posture flag that holds; `context` = neutral summary/value. */
  tone: "risk" | "context";
}

/**
 * Map a CA-host finding's raw value to a legible chip. The DCOM summary is shown
 * verbatim as neutral context; an ESC flag whose value is "true" (the weak condition
 * holds) becomes a risk-toned "present" chip rather than a confusing bare "true".
 * An unexpected value degrades to the raw value with neutral tone (never guessed).
 */
export function caFindingDisplay(f: Pick<CaNodeFindingOut, "prop" | "value">): CaFindingDisplay {
  if (f.prop === CA_PROP_DCOM) {
    return { badge: f.value.trim() || "DCOM", tone: "context" };
  }
  const holds = f.value.trim().toLowerCase() === "true";
  if (holds) return { badge: "present", tone: "risk" };
  return { badge: f.value.trim() || "—", tone: "context" };
}
