import { ExternalLink, Github, Linkedin, Mail } from "lucide-react";
import { Link } from "react-router-dom";

import { Logo } from "@/components/shell/Logo";
import { Badge } from "@/components/ui/badge";

interface LinkRow {
  label: string;
  value: string;
  href: string;
  icon: typeof Mail;
  /** mailto links stay in-app; web links open a new tab. */
  external: boolean;
}

const PORTFOLIO_URL = "https://n1ghtfury74.github.io/";
const ENGINEERING_BLOG_URL = "https://n1ghtfury74.github.io/blog/2026/11/05/building-wraith/";

const CONTACTS: LinkRow[] = [
  {
    label: "Portfolio",
    value: "n1ghtfury74.github.io",
    href: PORTFOLIO_URL,
    icon: ExternalLink,
    external: true,
  },
  {
    label: "Email",
    value: "mohamedhany.de@outlook.com",
    href: "mailto:mohamedhany.de@outlook.com",
    icon: Mail,
    external: false,
  },
  {
    label: "LinkedIn",
    value: "linkedin.com/in/mohamed-hanii-0291031aa",
    href: "https://linkedin.com/in/mohamed-hanii-0291031aa",
    icon: Linkedin,
    external: true,
  },
  {
    label: "GitHub",
    value: "github.com/N1ghtFury74",
    href: "https://github.com/N1ghtFury74",
    icon: Github,
    external: true,
  },
];

/** The WRAITH workflow, end to end — what the tool actually does. */
const FLOW: { step: string; title: string; body: string }[] = [
  {
    step: "01",
    title: "Acquire, offline",
    body: "Point WRAITH at dead-disk DC artifacts — ntds.dit, the SYSTEM hive, and SYSVOL — from a forensic image. Nothing touches the live estate; zero packets leave the host.",
  },
  {
    step: "02",
    title: "Parse & decrypt",
    body: "The ESE database, registry hives, and GPOs are parsed with battle-tested libraries, secrets decrypted via the PEK path — each object stamped with source file, image hash, and directory timestamps.",
  },
  {
    step: "03",
    title: "Map the capability graph",
    body: "In v1.0, identities, group membership, ACLs, GPO application, and AD CS topology become a capability graph — who can do what to whom across the domain, built natively for the offline case.",
  },
  {
    step: "04",
    title: "Ask questions of the terrain",
    body: "Walk the graph, run prebuilt hunts, read per-entity dossiers, and trace paths to Tier-0 to learn who controls what before you hunt — then export to BloodHound, every finding carrying its forensic provenance.",
  },
];

const GUARANTEES = [
  "Offline — no network egress",
  "Provenance on every entity & edge",
  "Secrets encrypted & redacted",
  "Deterministic",
  "Authorized use only",
];

/** Tight, scannable supporting points under the lead — the "what you get". */
const POINTS: { title: string; body: string }[] = [
  {
    title: "Offline by construction",
    body: "zero packets leave the host, and every entity and edge carries its forensic provenance.",
  },
  {
    title: "A capability graph, not a dump",
    body: "identities, groups, ACLs, GPOs and AD CS resolved into who can do what to whom — with per-entity dossiers and risk findings.",
  },
  {
    title: "Answers the questions that shape a hunt",
    body: "who can reach Tier-0, what a given principal controls, and where the paths run.",
  },
];

/**
 * Standalone (not case-scoped) About page. WRAITH-first: what the tool is, how
 * it's used (v1.0 AD scope), and the guarantees it holds. The author block is a
 * short brief; the portfolio lives in the Contact list — no phone, no address.
 * No external image is fetched (offline); only the links below leave the app, on click.
 */
export function AboutPage() {
  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 sm:py-10">
      {/* WRAITH — the focus. Two columns on wide screens so the content fills the
          width instead of floating in a lone centered strip: the product lead +
          scannable points on the left, the "where it stands" (v1.0 vs roadmap)
          framing on the right. */}
      <section className="rounded-lg border border-border bg-surface/60 p-5 elevated sm:p-6">
        <div className="grid gap-6 lg:grid-cols-5 lg:gap-8">
          {/* Left — identity, lead, scannable points */}
          <div className="lg:col-span-3">
            <div className="flex items-start gap-4">
              <Logo className="size-12 shrink-0" title="WRAITH" />
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <h1 className="text-hero font-semibold tracking-tight text-foreground">WRAITH</h1>
                  <Badge variant="accent" className="translate-y-px">
                    v1.0
                  </Badge>
                </div>
                <p className="mt-1 text-body font-medium text-foreground-secondary">
                  Know what the attacker knows.
                </p>
              </div>
            </div>

            <p className="mt-5 text-body leading-relaxed text-foreground-secondary">
              WRAITH is a{" "}
              <span className="text-foreground">capability &amp; behavioral-baselining platform</span>{" "}
              for the terrain you are about to hunt in.{" "}
              <span className="text-foreground">Version 1.0 is the Active Directory release</span>:
              point it at a dead-disk Domain Controller image and it reconstructs the attacker&apos;s
              privilege map, <span className="text-foreground">entirely offline</span>.
            </p>

            <ul className="mt-4 space-y-2.5">
              {POINTS.map(({ title, body }) => (
                <li key={title} className="flex gap-2.5">
                  <span
                    className="mt-[0.3rem] size-1.5 shrink-0 rounded-full bg-accent"
                    aria-hidden="true"
                  />
                  <p className="text-caption leading-relaxed text-muted-foreground">
                    <span className="font-semibold text-foreground-secondary">{title}</span> —{" "}
                    {body}
                  </p>
                </li>
              ))}
            </ul>
          </div>

          {/* Right — where it stands: v1.0 = AD now, baselining = roadmap. */}
          <div className="lg:col-span-2">
            <div className="h-full rounded-md border border-border bg-surface-raised/50 p-4">
              <p className="eyebrow mb-3">Where it stands</p>
              <div className="space-y-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="available">Now</Badge>
                    <p className="text-body-sm font-semibold text-foreground">
                      v1.0 · Active Directory
                    </p>
                  </div>
                  <p className="mt-1.5 text-caption leading-relaxed text-muted-foreground">
                    Offline AD relationship mapping — the attacker&apos;s privilege map, rebuilt from
                    a dead-disk DC image.
                  </p>
                </div>
                <div className="h-px bg-border" />
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline">Next</Badge>
                    <p className="text-body-sm font-semibold text-foreground-secondary">
                      Behavioral baselining
                    </p>
                  </div>
                  <p className="mt-1.5 text-caption leading-relaxed text-muted-foreground">
                    The same model is built to baseline users, processes &amp; hosts. On the roadmap
                    — the locked Baselining module holds its slot today.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* How it's used + the guarantees it holds. Four steps span the wide column. */}
      <section className="mt-5 rounded-lg border border-border bg-surface/60 p-5 elevated sm:p-6">
        <p className="eyebrow mb-4">How it&apos;s used</p>
        <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {FLOW.map(({ step, title, body }) => (
            <li key={step} className="rounded-md border border-border bg-surface-raised/50 p-4">
              <div className="flex items-baseline gap-2">
                <span className="font-mono text-caption text-accent">{step}</span>
                <p className="text-body-sm font-semibold text-foreground">{title}</p>
              </div>
              <p className="mt-1.5 text-caption leading-relaxed text-muted-foreground">{body}</p>
            </li>
          ))}
        </ol>

        <div className="mt-6 h-px bg-border" />

        <div className="mt-6 flex flex-wrap gap-2">
          {GUARANTEES.map((g) => (
            <span
              key={g}
              className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface-raised/60 px-3 py-1 text-micro font-medium text-muted-foreground"
            >
              <span className="size-1 shrink-0 rounded-full bg-accent/70" aria-hidden="true" />
              {g}
            </span>
          ))}
        </div>

        <p className="mt-5 text-caption text-muted-foreground">
          Every guarantee has a cost.{" "}
          <Link
            to="/limitations"
            className="font-medium text-accent hover:underline focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          >
            Read what offline leaves out, and why every gap is counted
          </Link>
          .
        </p>

        <p className="mt-3 text-caption text-muted-foreground">
          How it&apos;s built — a module-by-module engineering deep-dive on the parsing, the edge
          engine, and the offline guarantees:{" "}
          <a
            href={ENGINEERING_BLOG_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 font-medium text-accent hover:underline focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          >
            Building WRAITH
            <ExternalLink className="size-3" aria-hidden="true" />
          </a>
          .
        </p>
      </section>

      {/* Author — a short brief; full profile lives on the portfolio (Contact list).
          Bio and contact sit side by side on wide screens. */}
      <section className="mt-5 rounded-lg border border-border bg-surface/60 p-5 elevated sm:p-6">
        <div className="grid gap-6 lg:grid-cols-5 lg:gap-8">
          <div className="lg:col-span-3">
            <div className="flex items-start gap-4">
              <div
                className="flex size-12 shrink-0 items-center justify-center rounded-lg bg-accent text-title font-semibold tracking-tight text-accent-foreground"
                aria-hidden="true"
              >
                MH
              </div>
              <div className="min-w-0">
                <p className="eyebrow mb-1">Built by</p>
                <h2 className="text-display text-foreground">Mohamed Hany</h2>
                <p className="text-body text-accent">Threat Hunting &amp; Detection Engineer</p>
              </div>
            </div>

            <p className="mt-5 text-body leading-relaxed text-foreground-secondary">
              A guy who loves to learn how things work, break them down, and develop solutions. I
              turn curiosity into research, research into knowledge, and knowledge into teaching
              others. Day to day that means hunting adversaries across endpoint, identity, network
              and cloud telemetry, maintaining the detection library that catches them, and running a
              threat intelligence program that tells both where to look — then writing it up so other
              defenders can use it.
            </p>
          </div>

          <div className="lg:col-span-2">
            <p className="eyebrow mb-2">Contact</p>
            <div className="space-y-2">
              {CONTACTS.map(({ label, value, href, icon: Icon, external }) => (
                <a
                  key={label}
                  href={href}
                  {...(external ? { target: "_blank", rel: "noopener noreferrer" } : {})}
                  className="flex items-center gap-3 rounded-md border border-border bg-surface-raised px-3 py-2.5 text-body transition-colors hover:border-border-strong hover:bg-muted focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                >
                  <Icon className="size-4 shrink-0 text-accent" />
                  <span className="w-16 shrink-0 text-muted-foreground">{label}</span>
                  <span className="min-w-0 flex-1 break-anywhere font-mono text-body-sm text-foreground">
                    {value}
                  </span>
                </a>
              ))}
            </div>
          </div>
        </div>
      </section>

      <p className="mt-6 text-center text-micro text-muted-foreground">
        Offline · dead-disk · no network egress · authorized use only
      </p>
    </div>
  );
}
