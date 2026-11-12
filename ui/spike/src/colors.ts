// Node color-by-kind map for the spike. Kinds come straight from the canonical
// store (principal_type / container_type / adcs_type / "GPO").

export const KIND_COLORS: Record<string, string> = {
  User: "#5ac8fa",
  Computer: "#ff9f0a",
  Group: "#ff6482",
  Container: "#6b7280",
  Domain: "#bf5af2",
  OU: "#30d158",
  GPO: "#ffd60a",
  CertTemplate: "#64d2ff",
  EnterpriseCA: "#64d2ff",
  RootCA: "#64d2ff",
  AIACA: "#64d2ff",
  NTAuthStore: "#64d2ff",
  IssuancePolicy: "#64d2ff",
};

export const DEFAULT_COLOR = "#8a97ab";

export function colorForKind(kind: string): string {
  return KIND_COLORS[kind] ?? DEFAULT_COLOR;
}

// Kinds present in a graph, for the legend.
export function kindsOf(kinds: Iterable<string>): string[] {
  return Array.from(new Set(kinds)).sort();
}
