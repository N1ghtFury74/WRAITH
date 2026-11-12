import { cn } from "@/lib/utils";

interface Props {
  /** Extra classes (sizing comes from the caller, e.g. `size-7`). */
  className?: string;
  /** Decorative by default; pass a title to expose an accessible name. */
  title?: string;
}

/**
 * The WRAITH mark — direction "D3 · Monolith": a rounded-square accent tile with a
 * knockout "W" wordmark-monogram. Wordmark/monogram-led (the premium, security-brand
 * route — Elastic / CrowdStrike / Wiz), deliberately NOT a drawn mascot (that route
 * read amateur in code and was rejected twice). The tile is self-contained — accent
 * cyan field + dark knockout letter — so it reads as a crisp product/app icon at
 * every size (strongest 16px favicon of the set) and is theme-independent by design
 * (same chip on light and dark). Original SVG geometry, inline, offline. Alternate
 * directions (Stencil W, Rift, Spectre) + the chooser page live in ui/web/brand/.
 */
export function Logo({ className, title }: Props) {
  return (
    <svg
      viewBox="0 0 48 48"
      className={cn("shrink-0", className)}
      role={title ? "img" : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
    >
      {title ? <title>{title}</title> : null}
      {/* accent tile */}
      <rect x="3" y="3" width="42" height="42" rx="11" fill="#0891b2" />
      {/* knockout W */}
      <path
        fill="#06151b"
        fillRule="evenodd"
        d="M10.5 14 L15.5 14 L19.2 29.5 L23 17.5 L25 17.5 L28.8 29.5 L32.5 14 L37.5 14 L31.6 34 L26.6 34 L24 25.5 L21.4 34 L16.4 34 Z"
      />
    </svg>
  );
}
