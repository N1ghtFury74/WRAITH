import { useCallback, useEffect, useMemo, useState } from "react";

import {
  normalizePref,
  nextPref,
  resolveTheme,
  THEME_KEY,
  ThemeContext,
  type ThemeContextValue,
  type ThemePref,
} from "@/hooks/useTheme";
import { readLs, writeLs } from "@/lib/storage";

/**
 * Apply a preference to `<html>`: set `data-theme` for an explicit choice, or
 * REMOVE it for `system` so the `prefers-color-scheme` media query takes over
 * (mirrors the inline FOUC script in index.html). Side-effecting.
 */
function applyPref(pref: ThemePref): void {
  const root = document.documentElement;
  if (pref === "system") delete root.dataset.theme;
  else root.dataset.theme = pref;
}

const mql = (): MediaQueryList | null =>
  typeof window !== "undefined" && typeof window.matchMedia === "function"
    ? window.matchMedia("(prefers-color-scheme: dark)")
    : null;

/**
 * Single theme store (doc 10 §2.2) over `localStorage["wraith.theme"]`. Keeps a
 * live `matchMedia` listener so a `system` preference re-resolves when the OS
 * flips — the graph palette follows because it reads `resolvedTheme`. Every
 * storage access goes through the try/catch `readLs`/`writeLs` helpers. Wrap the
 * app once; all consumers share this one state so the TopBar toggle and the
 * canvas never diverge.
 */
export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [pref, setPrefState] = useState<ThemePref>(() =>
    normalizePref(readLs<ThemePref>(THEME_KEY, "system")),
  );
  const [systemPrefersDark, setSystemPrefersDark] = useState<boolean>(() => mql()?.matches ?? false);

  useEffect(() => {
    const m = mql();
    if (!m) return;
    const onChange = (e: MediaQueryListEvent) => setSystemPrefersDark(e.matches);
    setSystemPrefersDark(m.matches);
    m.addEventListener("change", onChange);
    return () => m.removeEventListener("change", onChange);
  }, []);

  useEffect(() => {
    applyPref(pref);
  }, [pref]);

  const setPref = useCallback((next: ThemePref) => {
    const n = normalizePref(next);
    setPrefState(n);
    writeLs(THEME_KEY, n);
  }, []);

  const value = useMemo<ThemeContextValue>(
    () => ({
      pref,
      resolvedTheme: resolveTheme(pref, systemPrefersDark),
      setPref,
      cycle: () => setPref(nextPref(pref)),
    }),
    [pref, systemPrefersDark, setPref],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}
