import { useEffect, useState } from "react";

/**
 * Subscribe to a CSS media query (e.g. `"(max-width: 767px)"`). Returns whether
 * it currently matches and updates on change. SSR/no-`matchMedia` safe (returns
 * `false`). Used to switch the secondary panel between an inline column (wide)
 * and an off-canvas flyout (narrow) so only one mounts at a time.
 */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState<boolean>(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
    return window.matchMedia(query).matches;
  });

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const m = window.matchMedia(query);
    const onChange = () => setMatches(m.matches);
    onChange();
    m.addEventListener("change", onChange);
    return () => m.removeEventListener("change", onChange);
  }, [query]);

  return matches;
}
