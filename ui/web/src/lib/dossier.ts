import type { Glossary, NodeDossier } from "@/lib/api";

/** Notable UAC/flag badges for a node (shared by the inspector + dossier page). */
export function uacBadges(d: Pick<NodeDossier, "uac">): string[] {
  const u = d.uac;
  if (!u) return [];
  const out: string[] = [];
  if (u.enabled === false || u.account_disabled) out.push("disabled");
  if (u.enabled === true && !u.account_disabled) out.push("enabled");
  if (u.trusted_for_delegation) out.push("unconstrained deleg");
  if (u.trusted_to_auth_for_delegation) out.push("constrained deleg");
  if (u.dont_require_preauth) out.push("AS-REP roastable");
  if (u.password_not_required) out.push("pwd not required");
  if (u.dont_expire_password) out.push("pwd never expires");
  return out;
}

/** Format an access mask as hex (ACE rights are a bitmask), or an em dash. */
export function accessMask(mask: number | null | undefined): string {
  if (mask === null || mask === undefined) return "—";
  return `0x${(mask >>> 0).toString(16).toUpperCase()}`;
}

/** Format an ISO timestamp, or an em dash. */
export function ts(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toISOString().replace("T", " ").replace("Z", " UTC");
}

/** The verb phrase + rationale for an edge kind, from the static glossary (§5). */
export interface EdgeAction {
  /** The action verb phrase, e.g. "has full control of" / "can reset the password of". */
  action: string;
  /** Why a hunter cares (glossary "why"), or null when the kind is unknown. */
  why: string | null;
  /** True when the edge kind is not in the glossary (a glossary gap, never guessed). */
  unknown: boolean;
}

/**
 * Resolve an edge kind to its plain-language action + rationale (doc 21 §4/§5).
 * Pure. An edge kind missing from the glossary yields a NEUTRAL phrase (never a
 * guessed abuse) so the row still reads as a relationship with the raw kind shown.
 */
export function edgeAction(glossary: Glossary | undefined, kind: string): EdgeAction {
  const e = glossary?.edges[kind];
  if (!e) return { action: `has a ${kind} relationship over`, why: null, unknown: true };
  return { action: e.action, why: e.why, unknown: false };
}

/** The one-phrase caption for a node/UAC flag, or null when not in the glossary. */
export function flagCaption(glossary: Glossary | undefined, flag: string): string | null {
  const f = glossary?.flags[flag];
  return f?.why ?? f?.grants ?? null;
}
