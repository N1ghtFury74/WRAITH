import { CheckCircle2, CircleSlash, Lightbulb, TriangleAlert } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import type { CoverageReport } from "@/lib/api";
import { coverageVerdict } from "@/lib/coverageNarrative";

/**
 * The plain-language coverage verdict banner (design §5): a prominent, honest
 * "because you gave X you get A; missing Z so no D" rendered above the detailed
 * coverage matrix. Pure render of the existing CoverageReport.
 */
export function CoverageVerdict({ coverage }: { coverage: CoverageReport }) {
  const v = coverageVerdict(coverage);

  return (
    <div className="space-y-3 rounded-lg border border-border bg-surface-raised/50 p-4">
      {/* Gains */}
      {v.present.length > 0 && v.gains.length > 0 ? (
        <p className="text-body-sm leading-5 text-foreground-secondary">
          Because you provided{" "}
          {v.present.map((p, i) => (
            <span key={p}>
              <span className="font-medium text-foreground">{p}</span>
              {i < v.present.length - 1 ? ", " : ""}
            </span>
          ))}
          , you will get:
        </p>
      ) : v.present.length > 0 ? (
        <p className="text-body-sm text-foreground-secondary">
          You provided{" "}
          <span className="font-medium text-foreground">{v.present.join(", ")}</span>.
        </p>
      ) : (
        <p className="text-body-sm text-degraded">
          No artifacts yet — add the NTDS database to produce a graph.
        </p>
      )}

      {v.gains.length > 0 ? (
        <ul className="space-y-1">
          {v.gains.map((g) => (
            <li key={g} className="flex items-start gap-2 text-body-sm text-foreground">
              <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-available" />
              {g}
            </li>
          ))}
        </ul>
      ) : null}

      {/* Losses */}
      {v.losses.length > 0 ? (
        <div className="space-y-1 border-t border-border pt-3">
          <p className="eyebrow text-unavailable">You will not get</p>
          <ul className="space-y-1">
            {v.losses.map((l) => (
              <li key={l.label} className="flex items-start gap-2 text-body-sm text-foreground-secondary">
                <CircleSlash className="mt-0.5 size-3.5 shrink-0 text-unavailable" />
                <span>
                  <span className="text-foreground">{l.label}</span>
                  {l.note ? <span className="text-muted-foreground"> — {l.note}</span> : null}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {/* Degraded */}
      {v.degraded.length > 0 ? (
        <div className="space-y-1">
          <p className="eyebrow text-degraded">Partial</p>
          <ul className="space-y-1">
            {v.degraded.map((d) => (
              <li key={d.label} className="flex items-start gap-2 text-body-sm text-foreground-secondary">
                <TriangleAlert className="mt-0.5 size-3.5 shrink-0 text-degraded" />
                <span>
                  <span className="text-foreground">{d.label}</span>
                  {d.note ? <span className="text-muted-foreground"> — {d.note}</span> : null}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {/* Unlock hints */}
      {v.unlockHints.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2 border-t border-border pt-3">
          <span className="flex items-center gap-1.5 text-body-sm font-medium text-foreground">
            <Lightbulb className="size-3.5 text-accent" /> To unlock more, add:
          </span>
          {v.unlockHints.map((h) => (
            <Badge key={h} variant="accent">
              {h}
            </Badge>
          ))}
        </div>
      ) : null}
    </div>
  );
}
