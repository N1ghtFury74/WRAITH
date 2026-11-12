import { CheckCircle2, CircleSlash, Lock, TriangleAlert } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import type { CapabilityCoverage, CoverageReport, CoverageStatus } from "@/lib/api";
import { cn } from "@/lib/utils";

const STATUS_META: Record<
  CoverageStatus,
  { icon: typeof CheckCircle2; tone: string; badge: "available" | "degraded" | "unavailable"; label: string }
> = {
  available: { icon: CheckCircle2, tone: "text-available", badge: "available", label: "available" },
  degraded: { icon: TriangleAlert, tone: "text-degraded", badge: "degraded", label: "degraded" },
  unavailable: { icon: CircleSlash, tone: "text-unavailable", badge: "unavailable", label: "unavailable" },
};

function isReserved(cap: CapabilityCoverage): boolean {
  return cap.reasons.some((r) => r.gap_class.startsWith("reserved_pass_not_wired:"));
}

function CapabilityRow({ cap }: { cap: CapabilityCoverage }) {
  const meta = STATUS_META[cap.status];
  const Icon = meta.icon;
  const reserved = isReserved(cap);
  return (
    <li className="flex gap-3 border-b border-border/60 py-3 last:border-0">
      <Icon className={cn("mt-0.5 size-4 shrink-0", meta.tone)} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-body-sm font-semibold text-foreground">{cap.label}</span>
          <Badge variant="outline">tier {cap.tier}</Badge>
          <Badge variant={meta.badge}>{meta.label}</Badge>
          {reserved ? (
            <Badge variant="default" className="gap-1">
              <Lock className="size-2.5" /> stored · pass not wired
            </Badge>
          ) : null}
        </div>
        {cap.reasons.length > 0 ? (
          <ul className="mt-1 space-y-0.5">
            {cap.reasons.map((r) => (
              <li key={`${r.missing_artifact_id}:${r.gap_class}`} className="text-caption text-muted-foreground">
                {r.note}
                <span className="ml-1 font-mono text-micro text-muted-foreground">
                  ({r.gap_class})
                </span>
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </li>
  );
}

/** Live artifact→capability matrix (doc 14 §2) — updates as files are added. */
export function CoveragePanel({ coverage }: { coverage: CoverageReport }) {
  const counts = coverage.capabilities.reduce(
    (acc, c) => {
      acc[c.status] += 1;
      return acc;
    },
    { available: 0, degraded: 0, unavailable: 0 } as Record<CoverageStatus, number>,
  );

  return (
    <div>
      <div className="mb-3 flex items-center gap-2">
        <Badge variant="available">{counts.available} available</Badge>
        <Badge variant="degraded">{counts.degraded} degraded</Badge>
        <Badge variant="unavailable">{counts.unavailable} unavailable</Badge>
      </div>
      <ul>
        {coverage.capabilities.map((cap) => (
          <CapabilityRow key={cap.capability_id} cap={cap} />
        ))}
      </ul>
    </div>
  );
}
