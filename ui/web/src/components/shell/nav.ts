import { Activity, FileText, Layers, Network, ShieldAlert, type LucideIcon } from "lucide-react";

export interface NavItem {
  /** Route segment under `/case/:caseId/`. */
  segment: string;
  label: string;
  icon: LucideIcon;
  /** Reserved (disabled) — the shell shows a "coming soon" affordance. */
  reserved?: boolean;
  /** Requires a completed analysis before it is useful. */
  needsAnalysis?: boolean;
}

/**
 * Module rail (doc 13 §3). `Capability Graph | Dossiers | Risk` are the live FE-1
 * modules (graph canvas lands in FE-2 — the slot renders a placeholder now);
 * `Baselining` is the reserved disabled entry so adding it later is a route, not
 * a re-architecture.
 */
export const NAV_ITEMS: NavItem[] = [
  { segment: "ingest", label: "Case & Ingest", icon: Activity },
  { segment: "sources", label: "Sources", icon: Layers, needsAnalysis: true },
  { segment: "graph", label: "Capability Graph", icon: Network, needsAnalysis: true },
  { segment: "dossiers", label: "Dossiers", icon: FileText, needsAnalysis: true },
  { segment: "risk", label: "Risk", icon: ShieldAlert, needsAnalysis: true },
  { segment: "baselining", label: "Baselining", icon: Activity, reserved: true },
];
