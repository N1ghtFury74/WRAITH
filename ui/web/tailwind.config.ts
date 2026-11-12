import type { Config } from "tailwindcss";

// Dark-first SOC palette: a near-black layered surface stack (zinc-950/900),
// one restrained cyan accent for interactive, Tier-0 red, amber for degraded,
// green for available. Tokens are CSS variables (see src/index.css) so the whole
// theme is one file to retune. No runtime; Tailwind JIT emits only used classes.
const config: Config = {
  // Attribute-scoped theming (doc 10 §2.1): any residual `dark:` utility resolves
  // against [data-theme="dark"] on <html>, not a `.dark` class. The real theme
  // switch is the CSS-var token blocks in index.css — this just keeps the door open.
  darkMode: ["selector", '[data-theme="dark"]'],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      // Formalized type scale (doc 10 §7.1) — the SINGLE source of UI type. Every
      // size+line-height is a named token so components never hand-roll
      // `text-[0.8125rem]`, `text-xs` or `text-2xl`. Inter UI / JetBrains Mono.
      // Weight is bundled ONLY on the sans title tokens (display/title); the body
      // tokens stay weight-free so mono stats/IDs keep their loaded 400/500 face
      // (JetBrains Mono ships 400+500 only — a bundled 600 would render faux-bold).
      // Dense (SOC-grade) scale — owner-approved shrink of the SEMANTIC tokens so
      // every page tightens uniformly (headings no longer tower over body). Only
      // the px/line-height shrink; the role→token contract + mono-value rule in
      // index.css still hold. body13 / body-sm12 / caption11.5 / micro11 stay
      // distinct rungs via weight+color (they're intentionally close here).
      fontSize: {
        hero: ["1.0625rem", { lineHeight: "1.45rem" }], // 17/23.2 About hero, headline stat numbers (VERY-DENSE)
        display: ["0.9375rem", { lineHeight: "1.3rem", fontWeight: "600" }], // 15/20.8/600 page+dossier title
        title: ["0.9375rem", { lineHeight: "1.3rem", fontWeight: "600" }], // 15/20.8/600 avatar monogram
        body: ["0.75rem", { lineHeight: "1.1rem" }], // 12/17.6 default UI text (card/section title = body+600)
        "body-sm": ["0.71875rem", { lineHeight: "1rem" }], // 11.5/16 dense rows, dossier fields
        caption: ["0.6875rem", { lineHeight: "0.9rem" }], // 11/14.4 secondary metadata
        micro: ["0.65625rem", { lineHeight: "0.85rem" }], // 10.5/13.6 forensic detail, counts
      },
      colors: {
        border: {
          DEFAULT: "hsl(var(--border) / <alpha-value>)",
          strong: "hsl(var(--border-strong) / <alpha-value>)",
        },
        input: "hsl(var(--input) / <alpha-value>)",
        ring: "hsl(var(--ring) / <alpha-value>)",
        background: "hsl(var(--background) / <alpha-value>)",
        foreground: {
          DEFAULT: "hsl(var(--foreground) / <alpha-value>)",
          secondary: "hsl(var(--foreground-secondary) / <alpha-value>)",
        },
        surface: {
          DEFAULT: "hsl(var(--surface) / <alpha-value>)",
          raised: "hsl(var(--surface-raised) / <alpha-value>)",
          overlay: "hsl(var(--surface-overlay) / <alpha-value>)",
        },
        muted: {
          DEFAULT: "hsl(var(--muted) / <alpha-value>)",
          foreground: "hsl(var(--muted-foreground) / <alpha-value>)",
        },
        accent: {
          DEFAULT: "hsl(var(--accent) / <alpha-value>)",
          foreground: "hsl(var(--accent-foreground) / <alpha-value>)",
        },
        available: "hsl(var(--available) / <alpha-value>)",
        degraded: "hsl(var(--degraded) / <alpha-value>)",
        unavailable: "hsl(var(--unavailable) / <alpha-value>)",
        tier0: "hsl(var(--tier0) / <alpha-value>)",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      borderRadius: {
        lg: "0.5rem",
        md: "0.375rem",
        sm: "0.25rem",
      },
      boxShadow: {
        raised: "var(--shadow-raised)",
        overlay: "var(--shadow-overlay)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        "indeterminate": {
          "0%": { transform: "translateX(-100%)" },
          "100%": { transform: "translateX(400%)" },
        },
      },
      animation: {
        "fade-in": "fade-in 0.2s ease-out",
        "indeterminate": "indeterminate 1.2s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};

export default config;
