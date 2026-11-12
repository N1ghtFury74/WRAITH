import { createContext, useContext } from "react";

/**
 * UI text-size (density) preference. Scales the WHOLE app by setting the root
 * `<html>` font-size, so every rem-based type/spacing token moves in lockstep —
 * the owner's display-scaling knob, independent of OS zoom / browser zoom.
 *
 *   compact     → 14px root (tighter than default)
 *   normal      → 16px root (the current dense look — the DEFAULT)
 *   comfortable → 18px root (roomier)
 *
 * `normal` is the authored default and sets NO attribute (CSS falls back to the
 * browser-default 16px root, exactly as the app shipped), mirroring how a
 * `system` theme leaves `data-theme` off.
 */
export type Density = "compact" | "normal" | "comfortable";

/** localStorage key. Reused across sessions; the FOUC script in index.html reads it. */
export const DENSITY_KEY = "wraith.density";

/** Left→right order for the segmented A− / A / A+ control (small → large). */
export const DENSITY_ORDER: readonly Density[] = ["compact", "normal", "comfortable"] as const;

/** Root `<html>` font-size (px) each density maps to — the single scaling source. */
export const DENSITY_PX: Record<Density, number> = {
  compact: 14,
  normal: 16,
  comfortable: 18,
};

/** Narrow any stored/arbitrary value to a valid {@link Density}; default `normal`. */
export function normalizeDensity(value: unknown): Density {
  return value === "compact" || value === "normal" || value === "comfortable" ? value : "normal";
}

export interface DensityContextValue {
  /** The user's stored text-size preference. */
  density: Density;
  /** Set an explicit preference (persisted). */
  setDensity: (density: Density) => void;
}

/** Shared density store, provided by {@link ../components/providers/DensityProvider}. */
export const DensityContext = createContext<DensityContextValue | null>(null);

/**
 * Read the shared density state. Falls back to a `normal` no-op stub when no
 * provider is mounted (standalone print routes / tests) so callers never crash.
 */
export function useDensity(): DensityContextValue {
  const ctx = useContext(DensityContext);
  if (ctx) return ctx;
  return { density: "normal", setDensity: () => {} };
}
