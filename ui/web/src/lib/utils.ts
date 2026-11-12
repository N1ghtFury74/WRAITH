import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Merge conditional + conflicting Tailwind classes (shadcn `cn` convention). */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/** Human-readable byte size (deterministic, binary units). */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[i]}`;
}

/** Short SHA display: first 12 hex chars (full value stays available on hover). */
export function shortSha(sha: string | null | undefined): string {
  if (!sha) return "—";
  return sha.length <= 12 ? sha : `${sha.slice(0, 12)}…`;
}

/**
 * Derive a filesystem-safe case id from a friendly name, matching the server
 * rule `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,126}$`: lowercase, invalid runs -> `-`,
 * collapse repeats, strip a leading non-`[a-z0-9_]`, trim trailing `-`/`.`, cap
 * at 127 chars. Returns `""` only when nothing usable remains (caller blocks).
 * "Test 1" -> "test-1".
 */
export function slugifyCaseId(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/\.{2,}/g, ".")
    .replace(/^[^a-z0-9_]+/, "")
    .replace(/[-.]+$/, "")
    .slice(0, 127);
}

/**
 * Mirror of the server's `slug_host_label` (wraith/api/ingest.py): lowercase,
 * map any char outside `[A-Za-z0-9_.-]` to `-`, trim leading/trailing `-`/`.`.
 * Returns the exact label the server will store, so the operator sees the truth.
 */
export function slugHostLabel(label: string): string {
  return label
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.-]/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "");
}

/** Format an ISO timestamp for display, or an em dash when absent/invalid. */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleDateString();
}
