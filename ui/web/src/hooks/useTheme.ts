import { createContext, useContext } from "react";

/** The three toggle states. `system` follows the OS `prefers-color-scheme`. */
export type ThemePref = "light" | "dark" | "system";
/** What the UI actually paints — what the graph canvas needs (never `system`). */
export type ResolvedTheme = "light" | "dark";

/** localStorage key (doc 10 §2.2). Reused across sessions; FOUC script reads it. */
export const THEME_KEY = "wraith.theme";

const PREFS: readonly ThemePref[] = ["light", "dark", "system"] as const;

/** Narrow any stored/arbitrary value to a valid {@link ThemePref}; default `system`. */
export function normalizePref(value: unknown): ThemePref {
  return value === "light" || value === "dark" || value === "system" ? value : "system";
}

/**
 * Resolve a preference + the OS signal into the concrete theme to paint. Pure and
 * deterministic (no DOM) so it is unit-testable:
 *   - `light`/`dark` → themselves (manual choice wins),
 *   - `system`       → `dark` when the OS prefers dark, else `light`.
 */
export function resolveTheme(pref: ThemePref, systemPrefersDark: boolean): ResolvedTheme {
  if (pref === "light" || pref === "dark") return pref;
  return systemPrefersDark ? "dark" : "light";
}

/** The next state in the three-way cycle light → dark → system → light. */
export function nextPref(pref: ThemePref): ThemePref {
  return PREFS[(PREFS.indexOf(pref) + 1) % PREFS.length];
}

export interface ThemeContextValue {
  /** The user's stored preference (`light`/`dark`/`system`). */
  pref: ThemePref;
  /** The concrete theme currently painted (never `system`) — the graph reads this. */
  resolvedTheme: ResolvedTheme;
  /** Set an explicit preference (persisted). */
  setPref: (pref: ThemePref) => void;
  /** Advance the three-way cycle (persisted). */
  cycle: () => void;
}

/** Shared theme store, provided by {@link ../components/providers/ThemeProvider}. */
export const ThemeContext = createContext<ThemeContextValue | null>(null);

/**
 * Read the shared theme state. Falls back to a neutral `dark`-resolved stub when
 * no provider is mounted (e.g. standalone print routes / tests) so callers never
 * crash.
 */
export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (ctx) return ctx;
  return { pref: "system", resolvedTheme: "dark", setPref: () => {}, cycle: () => {} };
}
