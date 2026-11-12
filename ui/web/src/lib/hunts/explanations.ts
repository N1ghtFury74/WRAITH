/**
 * Plain-English hunt explanations + per-category intent lines (Round 1 D).
 *
 * The operator runs the whole workflow from the UI with no external docs (memory
 * `ui-operate-everything-no-docs`), so each hunt needs an on-screen description. The
 * one-line subtitle in the rail is the hunt's own ``description``; this module adds,
 * for the hunts the domain expert authored in doc 09 §4, a richer structured note
 * (what it finds / why an attacker cares / how to read / caveat) shown when a hunt is
 * expanded, plus a one-line intent per hunter category. Pure data — no logic.
 */

export interface HuntNote {
  /** What the hunt finds. */
  finds: string;
  /** Why an attacker cares. */
  why: string;
  /** How to read the result. */
  read: string;
  /** The honesty caveat. */
  caveat: string;
}

/** One-line intent per hunter category (shown under the expanded category header). */
export const CATEGORY_INTENT: Record<string, string> = {
  "Privileged Access":
    "Who holds standing domain privilege — the crown-jewel rosters and the paths into them.",
  "Dangerous ACLs":
    "Who can rewrite security on Tier-0 — permission-based takeover, not group membership.",
  "Shadow Admins":
    "Hidden control of Tier-0 by principals that are in no admin group — the ACL backdoor.",
  "Credential Exposure":
    "Accounts whose credentials are crackable, recoverable, or dangerously over-permissive.",
  Delegation: "Kerberos delegation that lets one identity act as (impersonate) another.",
  "Stale/Risk": "Leftover privilege and hygiene problems — risk that lingers after it should.",
  Topology: "Trusts, domain controllers, and cross-boundary reach.",
  ADCS: "Certificate-services attack surface (synthetic-only in v1 until a real CA artifact is wired).",
};

/** Structured plain-English notes keyed by catalog query id (doc 09 §4). */
export const HUNT_NOTES: Record<string, HuntNote> = {
  "paths-to-tier0": {
    finds:
      "One shortest attacker path from every principal that can reach Tier Zero to the nearest Tier-0 target.",
    why: "This is the whole game: anyone on this list can become domain-dominant through some chain of abuses.",
    read: "Read each row as 'start here → these labelled hops → Tier Zero'; triage the shortest paths first.",
    caveat:
      "The count beside the query is the number of Tier-0 principals, NOT paths; control hops are grant-based (DENY ACEs not evaluated).",
  },
  "paths-from-domain-users": {
    finds: "The shortest path to Tier Zero from each effective member of Domain Users (any authenticated user).",
    why: "The blast-radius question: if any path exists, one phished low-priv account reaches domain compromise.",
    read: "Treat even one short path as critical — it is the worst case available to almost everyone.",
    caveat: "Membership is the effective (nested) closure; a chain is only as trustworthy as its weakest-confidence hop.",
  },
  "set-tier0": {
    finds: "The Tier-0 principals (classification + current effective members) with their one-hop neighbourhood.",
    why: "These are the crown-jewel identities — compromising any one IS domain compromise.",
    read: "The 'what must never fall' inventory and the set every path hunt aims at.",
    caveat: "Membership + classification (a set, not paths); the count is the number of Tier-0 principals.",
  },
  "set-domain-admins": {
    finds: "Every effective (nested + primary-group) member of Domain Admins, not just direct members.",
    why: "Domain Admins is full control of the domain — including members hidden behind group nesting.",
    read: "The true DA roster; investigate any member you didn't expect and any nesting that drags users in.",
    caveat: "The count is effective members, not a path count.",
  },
  "set-enterprise-admins": {
    finds: "Every effective (nested) member of Enterprise Admins — forest-wide authority.",
    why: "EA reaches every domain in the forest and the configuration partition — more valuable than DA.",
    read: "The forest-wide crown jewels; EA should be near-empty and tightly justified.",
    caveat: "Effective-member count, not paths; in a single-domain forest EA and DA often overlap.",
  },
  "set-schema-admins": {
    finds: "Every effective (nested) member of Schema Admins — can modify the AD schema (forest-wide, permanent).",
    why: "Schema changes replicate everywhere and are rarely needed — a standing member is a red flag.",
    read: "This group should be empty except during a deliberate schema change; justify or remove any member.",
    caveat: "Tier-0 classification but deliberately NOT a path-traversal target; effective-member count, not paths.",
  },
  "set-builtin-administrators": {
    finds: "Every effective (nested) member of the domain's built-in Administrators group.",
    why: "This is control of the domain controllers themselves — Tier-0.",
    read: "Read it as 'who is admin on the DCs'; scrutinise nested groups that expand it.",
    caveat: "Effective-member count, not paths; distinct from local Administrators on member servers (not collected).",
  },
  "set-domain-controllers": {
    finds: "Every effective (nested) member of the Domain Controllers group — the DC computer accounts.",
    why: "DCs hold the directory and its secrets; compromising a DC is domain compromise.",
    read: "The authoritative DC inventory and a cross-check that no unexpected account was nested in.",
    caveat: "DC accounts legitimately carry unconstrained-delegation flags that would alarm on a non-DC.",
  },
  "set-account-operators": {
    finds: "Every effective (nested) member of Account Operators — can manage most accounts and log on to DCs.",
    why: "A classic 'not-quite-DA but close' — can reset passwords / add members to reach higher privilege.",
    read: "Treat any member as a near-privileged identity to justify or strip.",
    caveat: "Offensively privileged but NOT domain-compromise-equivalent (AdminSDHolder protects Tier-0 groups).",
  },
  "set-enrollment-rights": {
    finds:
      "Principals holding an explicitly-granted Enroll / AutoEnroll right on a certificate template — the directly-granted enrollment population.",
    why: "Enrollment is the first step of most ESC chains: who can request a certificate decides who can even attempt the abuse.",
    read:
      "A roster, not paths. A GenericAll / AllExtendedRights holder has template CONTROL (ESC4) and shows under the ESC paths hunt, not here.",
    caveat:
      "SYNTHETIC-ONLY in v1: pure ntds Configuration-NC ACL facts, but untested on a real AD CS-bearing capture (Certipy parity pending). Verify before relying on it.",
  },
  "set-adcs-topology": {
    finds:
      "The AD CS PKI topology: enterprise CAs, the NTAuth store, root chains, template publication, and OID-policy links.",
    why: "The shape of the PKI is the map for every certificate attack — which CA serves the domain, which templates it publishes, what is NTAuth-trusted.",
    read: "Read it as the certificate-services terrain; it orients the enrollment-rights and ESC-path hunts.",
    caveat:
      "SYNTHETIC-ONLY in v1: topology edges are untested on a real AD CS-bearing capture (the reference DC has no usable AD CS). Treat as a lead to verify.",
  },
  "paths-to-adcs-esc": {
    finds: "Shortest attacker paths ending in an AD CS certificate-abuse (ESC) edge.",
    why: "ADCS escalations are often reachable from low privilege and yield durable DA-equivalent credentials.",
    read:
      "Read as 'low-privilege → certificate → Tier-0' and prioritise very highly. The domain-escalation ESCs (1/3/9/15/GoldenCert) sink at the Domain object; ESC4/10/13 sink at an intermediate that still needs the onward certificate step.",
    caveat:
      "SYNTHETIC-ONLY in v1: the ESC composition runs (it is pipeline-wired), but every ESC edge is inferred and untested on real captures until a CA artifact + Certipy parity gate flips it. ESC6/7/11/16 need the CA-host registry (not collected in v1) and are counted-undecidable — their absence here is NOT 'clean'. Treat any result as a lead to verify.",
  },
};
