import { ArrowLeft, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";

/**
 * Standalone, case-independent Limitations page (research 24, LOCKED). Reachable
 * ONLY from the About page — not in the ActivityBar or NAV_ITEMS. The copy is the
 * code-grounded honesty reference: every limit is the deliberate cost of the
 * offline guarantee, not a bug. Semantic tokens only, so it themes light+dark for
 * free and reads as a sibling of About. No external assets (offline).
 */

interface Section {
  title: string;
  /** Paragraph bodies; `strong` spans are marked inline where the copy bolds. */
  body: React.ReactNode[];
}

const SECTIONS: Section[] = [
  {
    title: "Snapshot in time",
    body: [
      "Everything WRAITH shows is a photograph of the directory at the moment it was imaged. A dead or backed-up DC can lag the live estate, so an edge that was true at capture may since have changed — every fact carries its source timestamp so you can see how old it is. WRAITH cannot replay a Domain Controller's transaction logs offline, so a directory that was shut down uncleanly is read best-effort and flagged as such; changes still sitting in uncommitted logs are not applied. Torn or unreadable records are counted and reported, never silently dropped.",
    ],
  },
  {
    title: "Group Policy is inferred, not resolved",
    body: [
      "Dead-disk, WRAITH can't evaluate WMI filters, security filtering, block-inheritance, link precedence or enforcement — so for the policy settings it parses it shows the full set of non-disabled links rather than hide a real path. It over-states, deliberately, within that scope; verify before you act. It also does not turn every way Group Policy can grant access into an edge, and some inputs simply can't be resolved offline — a member written as a name instead of a SID, a site-scoped link, a foreign-domain nested group, an unparseable policy file. WRAITH counts every one of those as a visible gap; it never silently drops one. For exactly what was and wasn't readable in your case, read the GPO coverage card.",
    ],
  },
  {
    title: "Certificate services are partly offline-undecidable",
    body: [
      "WRAITH reads the certificate-template and CA topology straight from the directory, and composes the ESC escalation paths it can prove offline. But several certificate attacks depend on facts that live only on the CA host's own registry (ESC6, ESC7, ESC11, ESC16, enrollment-agent restrictions) — a separate artifact WRAITH doesn't yet take. Those are marked undecidable and counted, never guessed. ESC9 and ESC10 depend on the DC's certificate-mapping configuration in its SYSTEM hive; without that hive, or when the setting is unset, they too are honestly undecidable. The relay-based attacks (ESC8 and friends) require live network coercion and are out of scope by definition. And the AD CS analytics as a whole are validated on synthetic fixtures today — trust the logic, treat the result as provisional until real-PKI parity lands.",
    ],
  },
  {
    title: "Cross-domain is not expanded",
    body: [
      "WRAITH today reasons over a single Domain Controller's directory. Group membership is expanded only for principals that are actually in the imaged directory; a member from another domain or forest resolves to a placeholder, and its onward membership is not followed offline. A path that crosses a trust may therefore be understated. Trusts themselves are shown as edges, but the foreign principals behind them stay placeholders.",
    ],
  },
  {
    title: "Access is as-imaged, not effective",
    body: [
      "WRAITH's control edges report the rights present in each object's security descriptor exactly as it was imaged — the same way an attacker enumerates them — not a full effective-access computation. It reads the granting (ALLOW) permissions and does not subtract DENY entries, so what you see is “what the ACL grants,” not “the net result after every deny and inheritance rule.” Rights whose scope WRAITH can't yet map, and default host-noise entries, are counted and set aside rather than turned into a misleading edge. A referenced account that isn't in the directory becomes a clearly-marked placeholder, not a fabricated identity.",
    ],
  },
  {
    title: "Secrets are recovered, never cracked",
    body: [
      "When the DC SYSTEM hive is present, WRAITH recovers the credential material inside the directory — hashes, history, Kerberos keys, LAPS and gMSA passwords, trust keys — and holds every one of them encrypted at rest, redacted by default, revealed only by an explicit command. It recovers; it never cracks, and it never shows a secret by default. Some of these (LAPSv2, gMSA, KDS and trust keys) are kept as raw encrypted blobs — nothing is lost, but WRAITH does not decrypt them offline. Without the SYSTEM hive, every secret in the directory stays encrypted and unreadable, and WRAITH says so.",
    ],
  },
];

export function LimitationsPage() {
  return (
    <div className="mx-auto max-w-3xl px-6 py-8">
      <Link
        to="/about"
        className="mb-6 inline-flex items-center gap-1.5 text-caption text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      >
        <ArrowLeft className="size-3.5" /> Back to About
      </Link>

      {/* Hero: title + descriptor + the framing intro */}
      <section className="rounded-lg border border-border bg-surface/60 p-6 elevated">
        <div className="flex items-start gap-4">
          <ShieldCheck className="mt-0.5 size-8 shrink-0 text-accent" />
          <div className="min-w-0">
            <h1 className="text-hero font-semibold tracking-tight text-foreground">Limitations</h1>
            <p className="mt-1 text-body text-foreground-secondary">
              What offline costs us, and why every gap is counted instead of guessed.
            </p>
          </div>
        </div>

        <p className="mt-6 text-body leading-relaxed text-foreground-secondary">
          WRAITH reads a dead Domain Controller the way an attacker reads a captured one: entirely
          offline, from forensic artifacts, with zero packets to any live system. That single
          guarantee — no network egress, ever — is what makes WRAITH safe to run against dead-disk
          evidence. It is also the source of every limitation on this page. A live tool can re-query
          a DC, compute effective access, read a CA host, replay transaction logs, and chase a
          principal across a trust. WRAITH does none of that, on purpose. So wherever a fact lives
          outside the evidence you handed it, or can only be known by touching the estate, WRAITH
          does the honest thing:{" "}
          <span className="text-foreground">
            it counts the gap and shows it as a gap, rather than invent an answer.
          </span>{" "}
          Nothing below is a bug. It is the deliberate cost of being offline, and the reason you can
          trust what WRAITH does show you.
        </p>
      </section>

      {/* One card per limitation group — siblings of the About section cards */}
      <div className="mt-5 space-y-4">
        {SECTIONS.map((s) => (
          <section key={s.title} className="rounded-lg border border-border bg-surface/60 p-5 elevated">
            <h2 className="eyebrow mb-3">{s.title}</h2>
            <div className="space-y-3">
              {s.body.map((p, i) => (
                <p key={i} className="text-body leading-relaxed text-foreground-secondary">
                  {p}
                </p>
              ))}
            </div>
          </section>
        ))}

        {/* "Reading your own case" — the live counterpoint, accent-framed */}
        <section className="rounded-lg border border-accent/30 bg-accent/5 p-5 elevated">
          <h2 className="eyebrow mb-3 text-accent">Reading your own case</h2>
          <p className="text-body leading-relaxed text-foreground-secondary">
            Every limitation here is a limitation of the method, not of your evidence. How much of{" "}
            <span className="text-foreground">your</span> case was actually readable — which GPOs
            parsed, which AD CS conditions were decidable, what the SYSTEM hive did or didn't
            unlock — is shown live on the{" "}
            <span className="text-foreground">AD CS and GPO coverage cards</span> and the{" "}
            <span className="text-foreground">confidence badge on every hunt result</span>. Where
            WRAITH couldn't know something, it will tell you it couldn't, and count it. That is the
            whole point.
          </p>
        </section>
      </div>

      <p className="mt-6 text-center text-micro text-muted-foreground">
        Offline · dead-disk · no network egress · authorized use only. Every gap is counted, never
        guessed.
      </p>
    </div>
  );
}
