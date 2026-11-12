import { useCallback, useEffect, useMemo, useState } from "react";

import {
  DENSITY_KEY,
  DensityContext,
  normalizeDensity,
  type Density,
  type DensityContextValue,
} from "@/hooks/useDensity";
import { readLs, writeLs } from "@/lib/storage";

/**
 * Apply a density to `<html>`: set `data-density` for an explicit non-default
 * choice, or REMOVE it for `normal` so CSS falls back to the browser-default
 * 16px root (the shipped look) — mirrors the inline FOUC script in index.html
 * and the ThemeProvider's `system` handling. Side-effecting.
 */
function applyDensity(density: Density): void {
  const root = document.documentElement;
  if (density === "normal") delete root.dataset.density;
  else root.dataset.density = density;
}

/**
 * Single text-size store over `localStorage["wraith.density"]`. Scales the whole
 * UI by the root font-size (every rem token follows), giving the owner a direct
 * size knob independent of OS / browser zoom. Storage goes through the try/catch
 * `readLs`/`writeLs` helpers; wrap the app once so the TopBar control and the
 * document root never diverge.
 */
export function DensityProvider({ children }: { children: React.ReactNode }) {
  const [density, setDensityState] = useState<Density>(() =>
    normalizeDensity(readLs<Density>(DENSITY_KEY, "normal")),
  );

  useEffect(() => {
    applyDensity(density);
  }, [density]);

  const setDensity = useCallback((next: Density) => {
    const n = normalizeDensity(next);
    setDensityState(n);
    writeLs(DENSITY_KEY, n);
  }, []);

  const value = useMemo<DensityContextValue>(() => ({ density, setDensity }), [density, setDensity]);

  return <DensityContext.Provider value={value}>{children}</DensityContext.Provider>;
}
