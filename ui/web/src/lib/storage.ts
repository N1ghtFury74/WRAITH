/**
 * Tiny localStorage JSON helpers that never throw (private mode / quota / SSR).
 * A failed read returns the fallback; a failed write is silently a no-op — UI
 * persistence is a nicety, never a correctness dependency.
 */

/** Read + JSON-parse a value, returning `fallback` on any access/parse error. */
export function readLs<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key);
    return raw === null ? fallback : (JSON.parse(raw) as T);
  } catch {
    return fallback;
  }
}

/** JSON-serialise + write a value, swallowing any access error (private mode/quota). */
export function writeLs(key: string, value: unknown): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage unavailable — non-fatal */
  }
}
