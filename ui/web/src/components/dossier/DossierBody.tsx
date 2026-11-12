import { AlertTriangle, FileKey2, GitMerge, KeyRound, Lock, Search, ShieldAlert, Users } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { PathSection } from "@/components/dossier/PathSection";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DenseBody,
  DenseCell,
  DenseHead,
  DenseRow,
  DenseTable,
  DenseTh,
} from "@/components/ui/dense-table";
import { Input } from "@/components/ui/input";
import { useTheme } from "@/hooks/useTheme";
import type {
  CaNodeFindingOut,
  DossierEdge,
  Glossary,
  GroupMemberRef,
  MergeOverlay,
  NodeDossier,
  PresentedAttribute,
} from "@/lib/api";
import { filterByLabel, groupInboundByController, kindBreakdown } from "@/lib/dossier/aces";
import { caFindingDisplay } from "@/lib/dossier/caFindings";
import { capList, expandToggleLabel } from "@/lib/dossier/overflow";
import { accessMask, edgeAction, flagCaption, ts, uacBadges } from "@/lib/dossier";
import { kindColor } from "@/lib/graph/encoding";
import { cn, shortSha } from "@/lib/utils";

interface Props {
  caseId: string;
  dossier: NodeDossier;
  /** The static rights glossary (annotations degrade gracefully when absent). */
  glossary?: Glossary;
  /** Include the two lazy pathfinding sections (8/9). Off for batch print. */
  includePaths?: boolean;
  /** Render links as plain text (print) vs navigable (screen). */
  variant?: "screen" | "print";
}

const INBOUND_CAP = 20;
const OUTBOUND_TARGET_CAP = 8;
const MEMBER_CAP = 50;
/** Tier-0 target names shown inline before the count is summarised (the rest are
 * reachable via the section's Show-all toggle — never a wall of inline names). */
const TIER0_INLINE_CAP = 6;

/** A relationship/narrative section — a top-level card sharing the About page's
 * section treatment (surface/60 + hairline + subtle elevation), so the dossier
 * reads as the same product (doc 10 §5.1). */
function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="dossier-section rounded-lg border border-border bg-surface/60 p-5 elevated sm:p-6">
      <h2 className="eyebrow mb-3">{title}</h2>
      {children}
    </section>
  );
}

/** A reference section — a clean boxed side-panel card matching the About page's
 * secondary-panel treatment (surface-raised/50), so the identity rail is no longer
 * a bare hairline list beside the boxed narrative (doc 10 §5.1). */
function Ref({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="dossier-section rounded-md border border-border bg-surface-raised/50 p-4">
      <h2 className="eyebrow mb-3">{title}</h2>
      {children}
    </section>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="flex flex-col gap-1">
      <span className="eyebrow">{label}</span>
      {/* break-anywhere (not break-all): prose like a description breaks at spaces,
          and a long single token (SID/DN/hash) wraps without chopping mid-word.
          leading-5 gives wrapped SID/DN rows comfortable breathing room. caption
          mono (one step below body-sm) optically matches the eyebrow label beside
          it — so the value no longer reads oversized next to a tiny label. */}
      <span className="break-anywhere font-mono text-caption leading-5 tabular-nums text-foreground">
        {value}
      </span>
    </div>
  );
}

/** A monospace at-a-glance stat chip. */
function Stat({ label, value, tone }: { label: string; value: React.ReactNode; tone?: "tier0" | "accent" }) {
  return (
    <div
      className={cn(
        "flex items-baseline gap-1.5 rounded-md border px-2.5 py-1",
        tone === "tier0"
          ? "border-tier0/40 bg-tier0/10"
          : tone === "accent"
            ? "border-accent/30 bg-accent/5"
            : "border-border bg-surface-raised/60",
      )}
    >
      <span className="font-mono text-body-sm font-medium tabular-nums text-foreground">{value}</span>
      <span className="text-caption text-muted-foreground">{label}</span>
    </div>
  );
}

/**
 * Actor/target name — a link on screen, plain text in print; id on hover.
 *
 * ALWAYS returns ONE grouped inline-flex unit (name + its Tier-0 badge), so when
 * dropped into a flex-wrap container the name and its own badge never separate and
 * never merge with a neighbouring entity's text. In `chip` mode the name renders
 * as a discrete bordered chip (for flex-wrap target lists — the outbound/member-of
 * style); otherwise it stays inline prose text (for sentences).
 */
function PartyName({
  caseId,
  nodeId,
  label,
  variant,
  tier0,
  chip,
}: {
  caseId: string;
  nodeId: string;
  label: string;
  variant: "screen" | "print";
  tier0?: boolean;
  chip?: boolean;
}) {
  const chipBase = "rounded border border-border px-2 py-0.5 font-mono text-caption";
  const name =
    variant === "screen" ? (
      <Link
        to={`/case/${encodeURIComponent(caseId)}/dossier/${encodeURIComponent(nodeId)}`}
        title={nodeId}
        className={cn(
          chip ? `${chipBase} text-accent hover:border-border-strong` : "font-medium text-accent hover:underline",
        )}
      >
        {label}
      </Link>
    ) : (
      <span
        title={nodeId}
        className={cn(chip ? `${chipBase} text-foreground` : "font-medium text-foreground")}
      >
        {label}
      </span>
    );
  return (
    <span className="inline-flex items-center gap-1">
      {name}
      {tier0 ? <Badge variant="tier0">Tier-0</Badge> : null}
    </span>
  );
}

/**
 * Inbound ACEs ("who controls this") — grouped by CONTROLLER principal so one
 * principal with many rights is one card (rights as sub-chips), not many rows
 * (doc 10 §5.2). Tier-0 controllers pinned first. The raw forensic line per ACE
 * sits behind a per-group "forensic detail" disclosure to reduce noise.
 */
function InboundAces({
  edges,
  caseId,
  glossary,
  selfKind,
  variant,
}: {
  edges: DossierEdge[];
  caseId: string;
  glossary: Glossary | undefined;
  selfKind: string;
  variant: "screen" | "print";
}) {
  const [showAll, setShowAll] = useState(false);
  const groups = useMemo(() => groupInboundByController(edges), [edges]);
  if (groups.length === 0)
    return <p className="text-caption text-muted-foreground">No principal controls this object.</p>;
  const shown = variant === "print" || showAll ? groups : groups.slice(0, INBOUND_CAP);
  const self = selfKind.toLowerCase();
  const tier0Count = groups.filter((g) => g.isTier0).length;

  return (
    <div className="space-y-2">
      <p className="text-body-sm text-muted-foreground">
        <span className="font-mono tabular-nums text-foreground">{groups.length}</span> controlling
        principal{groups.length === 1 ? "" : "s"}
        {tier0Count > 0 ? (
          <>
            {" · "}
            <span className="font-mono tabular-nums text-tier0">{tier0Count}</span> Tier-0
          </>
        ) : null}
        .
      </p>
      <div className="space-y-2">
        {shown.map((g) => (
          <InboundGroup key={g.controller.node_id} group={g} caseId={caseId} glossary={glossary} self={self} variant={variant} />
        ))}
      </div>
      {variant === "screen" && !showAll && groups.length > INBOUND_CAP ? (
        <Button size="xs" variant="secondary" onClick={() => setShowAll(true)}>
          Show all {groups.length}
        </Button>
      ) : null}
    </div>
  );
}

function InboundGroup({
  group,
  caseId,
  glossary,
  self,
  variant,
}: {
  group: ReturnType<typeof groupInboundByController>[number];
  caseId: string;
  glossary: Glossary | undefined;
  self: string;
  variant: "screen" | "print";
}) {
  const { controller, edges, rights } = group;
  return (
    <div className="rounded-md border border-border bg-surface-raised/50 p-3">
      <p className="text-body-sm leading-normal text-foreground">
        <PartyName caseId={caseId} nodeId={controller.node_id} label={controller.label} variant={variant} tier0={controller.is_tier0} />
        <span className="text-muted-foreground"> ({controller.kind})</span> controls this {self} via:
      </p>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {rights.map((r) => {
          const { action } = edgeAction(glossary, r);
          return (
            <Badge key={r} variant="degraded" title={action}>
              {r}
            </Badge>
          );
        })}
      </div>
      {variant === "screen" ? (
        <details className="group mt-1.5">
          <summary className="cursor-pointer list-none text-micro text-muted-foreground hover:text-foreground">
            forensic detail ({edges.length})
          </summary>
          <ul className="mt-1 space-y-0.5">
            {edges.map((e) => (
              <li
                key={e.edge_id}
                className="font-mono text-micro text-muted-foreground"
                title={e.attribute_name && e.object_type_guid ? e.object_type_guid : undefined}
              >
                {e.kind} · {accessMask(e.access_mask)}
                {e.attribute_name ? ` · via ${e.attribute_name}` : e.object_type_guid ? ` · via ${e.object_type_guid}` : ""}
                {e.confidence ? ` · ${e.confidence} confidence` : ""}
                {e.is_inherited ? " · inherited" : ""}
              </li>
            ))}
          </ul>
        </details>
      ) : (
        <ul className="mt-1 space-y-0.5">
          {edges.map((e) => (
            <li key={e.edge_id} className="font-mono text-micro text-muted-foreground">
              {e.kind} · {accessMask(e.access_mask)}
              {e.is_inherited ? " · inherited" : ""}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Outbound control — grouped by right kind with counts (not thousands of rows). */
function OutboundControl({
  edges,
  caseId,
  glossary,
  selfKind,
  variant,
}: {
  edges: DossierEdge[];
  caseId: string;
  glossary: Glossary | undefined;
  selfKind: string;
  variant: "screen" | "print";
}) {
  if (edges.length === 0) return <p className="text-caption text-muted-foreground">This object controls nothing.</p>;
  const byKind = new Map<string, DossierEdge[]>();
  for (const e of edges) (byKind.get(e.kind) ?? byKind.set(e.kind, []).get(e.kind)!).push(e);
  const kinds = [...byKind.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  const self = selfKind.toLowerCase();
  return (
    <div className="space-y-3">
      <p className="text-body-sm text-foreground">
        Controls <span className="font-mono tabular-nums">{edges.length}</span> object
        {edges.length === 1 ? "" : "s"} across <span className="font-mono tabular-nums">{kinds.length}</span>{" "}
        right kind{kinds.length === 1 ? "" : "s"}.
      </p>
      {kinds.map(([kind, list]) => (
        <OutboundKind key={kind} kind={kind} list={list} caseId={caseId} glossary={glossary} self={self} variant={variant} />
      ))}
    </div>
  );
}

function OutboundKind({
  kind,
  list,
  caseId,
  glossary,
  self,
  variant,
}: {
  kind: string;
  list: DossierEdge[];
  caseId: string;
  glossary: Glossary | undefined;
  self: string;
  variant: "screen" | "print";
}) {
  const [expanded, setExpanded] = useState(false);
  const { action, why } = edgeAction(glossary, kind);
  const targets = [...list].sort(
    (a, b) => Number(b.other.is_tier0) - Number(a.other.is_tier0) || a.other.label.localeCompare(b.other.label),
  );
  const tier0Targets = targets.filter((e) => e.other.is_tier0);
  // Inline Tier-0 callout: name the first few, then summarise the rest honestly.
  // Tied to the SAME expand state as the chips below, so "Show all" reveals every
  // Tier-0 name inline too — the "+N more" is never a dead end (the full count is
  // always on screen regardless).
  const tier0Inline = capList(tier0Targets, TIER0_INLINE_CAP, variant === "print" || expanded);
  // The target chips: a bounded head with a real show-all/collapse toggle; the
  // expanded set scrolls inside the card instead of blowing the layout open.
  const chips = capList(targets, OUTBOUND_TARGET_CAP, variant === "print" || expanded);
  return (
    <div className="border-b border-border/50 pb-2.5 last:border-0">
      <p className="text-body-sm leading-normal text-foreground">
        This {self} {action} <span className="font-mono tabular-nums">{list.length}</span> object
        {list.length === 1 ? "" : "s"} <span className="font-mono text-muted-foreground">({kind})</span>.
      </p>
      {why ? <p className="mt-0.5 text-caption leading-normal text-muted-foreground">{why}</p> : null}
      {tier0Targets.length > 0 ? (
        <p className="mt-1 text-caption leading-normal text-tier0">
          including <span className="font-mono tabular-nums">{tier0Targets.length}</span> Tier-0:{" "}
          {tier0Inline.shown.map((e) => e.other.label).join(", ")}
          {tier0Inline.hidden > 0 ? ` +${tier0Inline.hidden.toLocaleString("en-US")} more` : ""}
        </p>
      ) : null}
      <div
        className={cn(
          "mt-2 flex flex-wrap items-center gap-2",
          variant === "screen" && expanded && targets.length > OUTBOUND_TARGET_CAP
            ? "max-h-64 overflow-y-auto rounded-md border border-border bg-surface-raised/50 p-2"
            : "",
        )}
      >
        {chips.shown.map((e) => (
          <PartyName key={e.edge_id} caseId={caseId} nodeId={e.other.node_id} label={e.other.label} variant={variant} tier0={e.other.is_tier0} chip />
        ))}
      </div>
      {variant === "screen" && chips.hasMore ? (
        <Button size="xs" variant="secondary" className="mt-1.5" onClick={() => setExpanded((v) => !v)}>
          {expandToggleLabel(targets.length, expanded)}
        </Button>
      ) : null}
    </div>
  );
}

/** True when a member arrives via nesting/primary-group. Prefers the BACKEND
 * `is_nested` flag (single source of truth); falls back to the direct-MemberOf
 * id set only when the field is absent (graceful degrade, doc 10 §5.2). */
function memberIsNested(m: GroupMemberRef, directIds: Set<string>): boolean {
  if (typeof m.is_nested === "boolean") return m.is_nested;
  return !directIds.has(m.node_id);
}

/** Member confidence, read defensively (a parallel backend stream may add it). */
function memberConfidence(m: GroupMemberRef): string | null {
  const c = (m as { confidence?: string | null }).confidence;
  return typeof c === "string" && c ? c : null;
}

/**
 * Group members — summary-first (count + kind breakdown), a client-side filter,
 * Tier-0 pinned to the top, and a dense table with show-all (never silent
 * truncation) (doc 10 §5.2). Direct/nested uses the backend flag as the source.
 */
function GroupMembers({
  members,
  directIds,
  caseId,
  variant,
  resolved,
}: {
  members: GroupMemberRef[];
  directIds: Set<string>;
  caseId: string;
  variant: "screen" | "print";
  resolved: "light" | "dark";
}) {
  const [filter, setFilter] = useState("");
  const [showAll, setShowAll] = useState(false);

  const sorted = useMemo(
    () =>
      [...members].sort(
        (a, b) =>
          Number(b.is_tier0) - Number(a.is_tier0) ||
          (b.risk_score ?? -1) - (a.risk_score ?? -1) ||
          a.label.localeCompare(b.label),
      ),
    [members],
  );
  const breakdown = useMemo(() => kindBreakdown(members), [members]);
  const filtered = useMemo(() => filterByLabel(sorted, filter), [sorted, filter]);

  if (members.length === 0) {
    return (
      <p className="text-caption text-muted-foreground">
        No members. An empty privileged group is itself notable — a controller of it could still populate it.
      </p>
    );
  }
  const direct = members.filter((m) => !memberIsNested(m, directIds)).length;
  const nested = members.length - direct;
  const shown = variant === "print" || showAll ? filtered : filtered.slice(0, MEMBER_CAP);

  return (
    <div className="space-y-2">
      <p className="text-body-sm text-muted-foreground">
        <span className="font-mono tabular-nums text-foreground">{members.length}</span> effective (
        <span className="font-mono tabular-nums">{direct}</span> direct,{" "}
        <span className="font-mono tabular-nums">{nested}</span> nested)
      </p>
      {breakdown.length > 1 ? (
        <div className="flex flex-wrap gap-1">
          {breakdown.map((b) => (
            <span key={b.kind} className="rounded border border-border bg-surface-raised/60 px-2 py-0.5 font-mono text-caption tabular-nums text-muted-foreground">
              {b.count} {b.kind}
            </span>
          ))}
        </div>
      ) : null}
      {variant === "screen" && members.length > 10 ? (
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="filter members…"
            className="h-8 pl-8 text-body-sm"
            autoComplete="off"
          />
        </div>
      ) : null}
      <DenseTable maxHeightClass={variant === "screen" ? "max-h-[28rem]" : undefined}>
        <DenseHead>
          <DenseTh>Name</DenseTh>
          <DenseTh>Kind</DenseTh>
          <DenseTh>Via</DenseTh>
          <DenseTh numeric>Risk</DenseTh>
        </DenseHead>
        <DenseBody>
          {shown.map((m) => {
            const conf = memberConfidence(m);
            return (
              <DenseRow key={m.node_id}>
                <DenseCell>
                  <span className="flex items-center gap-2">
                    <span className="size-2 shrink-0 rounded-full" style={{ backgroundColor: kindColor(m.kind, resolved) }} />
                    <PartyName caseId={caseId} nodeId={m.node_id} label={m.label} variant={variant} tier0={m.is_tier0} />
                  </span>
                </DenseCell>
                <DenseCell className="text-caption text-muted-foreground">{m.kind}</DenseCell>
                <DenseCell className="text-caption text-muted-foreground">
                  {memberIsNested(m, directIds) ? "nested" : "direct"}
                  {conf ? <span className="ml-1 text-micro">· {conf}</span> : null}
                </DenseCell>
                <DenseCell numeric>
                  {m.risk_score !== null && m.risk_score > 0 ? m.risk_score : "—"}
                </DenseCell>
              </DenseRow>
            );
          })}
        </DenseBody>
      </DenseTable>
      {variant === "screen" && filtered.length === 0 ? (
        <p className="text-caption text-muted-foreground">No members match “{filter.trim()}”.</p>
      ) : null}
      {variant === "screen" && !showAll && filtered.length > MEMBER_CAP ? (
        <Button size="xs" variant="secondary" onClick={() => setShowAll(true)}>
          Show all {filtered.length}
        </Button>
      ) : null}
    </div>
  );
}

/** Render an unknown per-source attribute value for display (never a secret). */
function fmtValue(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v.length ? v : "(empty)";
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v);
}

/** Human copy for an entity-level divergence verdict (contract §3.2). */
const ENTITY_DIVERGENCE_COPY: Record<string, string> = {
  deleted_on_source:
    "Deleted (tombstoned) on one DC but live on another — presented live, because a deleted-on-one-DC principal is security-relevant.",
  candidate_lingering_object:
    "Live on one DC but absent on the authoritative DC past tombstone lifetime — a candidate lingering object, surfaced never dropped.",
};

/** One divergent attribute row with its three-state badge + per-source values. */
function PresentedAttributeRow({ attr }: { attr: PresentedAttribute }) {
  const contested = attr.state === "contested_unresolved";
  const entries = Object.entries(attr.value_by_source);
  return (
    <li className="rounded-md border border-border bg-surface-raised/50 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-body-sm text-foreground">{attr.attribute}</span>
        {contested ? (
          <Badge variant="unavailable" className="gap-1">
            <AlertTriangle className="size-2.5" /> contested
          </Badge>
        ) : (
          <Badge variant="degraded">resolved by merge</Badge>
        )}
      </div>
      {contested ? (
        <p className="mt-1 text-caption leading-normal text-unavailable">
          The sources disagreed and no tier could resolve this — WRAITH does not present a single
          value. Compare the per-source values below; never assume the benign one.
        </p>
      ) : (
        <p className="mt-1 text-caption text-muted-foreground">
          Presented value:{" "}
          <span className="font-mono text-foreground">{fmtValue(attr.presented_value)}</span>
        </p>
      )}
      {entries.length > 0 ? (
        <div className="mt-1.5 space-y-1">
          {entries.map(([sid, val]) => (
            <div key={sid} className="flex items-baseline gap-2 text-caption">
              <span className="shrink-0 font-mono text-muted-foreground" title={sid}>
                {sid.slice(0, 12)}…
              </span>
              <span className="break-anywhere font-mono text-foreground">{fmtValue(val)}</span>
            </div>
          ))}
        </div>
      ) : null}
    </li>
  );
}

/**
 * Multi-source merge overlay (contract §2.3 / §3): the honest divergence surface on
 * a folded dossier. A `contested_unresolved` attribute is badged and its benign
 * canonical value is NEVER presented as fact. Rendered only when a merge has run and
 * this is the folded (unscoped) view (`dossier.merge` present).
 */
function MergeOverlaySection({ merge }: { merge: MergeOverlay }) {
  const attrs = merge.presented_attributes ?? [];
  const hasEntity = Boolean(merge.entity_divergence);
  const hasAny = attrs.length > 0 || hasEntity || merge.secret_divergence;
  if (!hasAny) return null;
  const contestedCount = attrs.filter((a) => a.state === "contested_unresolved").length;

  return (
    <section className="dossier-section rounded-lg border border-degraded/40 bg-degraded/5 p-5 elevated sm:p-6">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <GitMerge className="size-4 text-degraded" />
        <h2 className="eyebrow text-degraded">Multi-source divergence</h2>
        {contestedCount > 0 ? <Badge variant="unavailable">{contestedCount} contested</Badge> : null}
      </div>
      <p className="mb-3 text-caption leading-normal text-foreground-secondary">
        This entity differs across the merged sources. Values are presented per the resolution ladder;
        a contested attribute is left un-chosen and flagged — never shown as the benign reading.
      </p>

      {hasEntity ? (
        <p className="mb-3 flex items-start gap-1.5 text-caption text-degraded">
          <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
          {ENTITY_DIVERGENCE_COPY[merge.entity_divergence as string] ?? merge.entity_divergence}
        </p>
      ) : null}

      {merge.secret_divergence ? (
        <p className="mb-3 flex items-start gap-1.5 text-caption text-degraded">
          <KeyRound className="mt-0.5 size-3.5 shrink-0" />
          Secret material differs across sources (un-replicated password). Both copies are kept,
          redacted — the value and hash are never shown.
        </p>
      ) : null}

      {attrs.length > 0 ? (
        <ul className="space-y-2">
          {attrs.map((a) => (
            <PresentedAttributeRow key={a.attribute} attr={a} />
          ))}
        </ul>
      ) : null}
    </section>
  );
}

/**
 * CA-host node-level findings (module 35b): ESC11/ESC16 on an EnterpriseCA node, the
 * DCOM activation summary on a CA host Computer node. Each finding is self-describing
 * (title + caption) and carries its own hive provenance — the honest caption states it
 * was decided from the CA host hive (not derivable from ntds.dit). Rendered only when
 * present; the API drops the key on a non-CA node, so a non-CA dossier shows nothing.
 */
function CaFindingsSection({ findings }: { findings: CaNodeFindingOut[] }) {
  if (findings.length === 0) return null;
  return (
    <section className="dossier-section rounded-lg border border-border bg-surface/60 p-5 elevated sm:p-6">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <h2 className="eyebrow">AD CS host configuration</h2>
        <Badge variant="degraded" title="Decided from the CA host registry hive — not derivable from ntds.dit.">
          from CA host hive
        </Badge>
      </div>
      <p className="mb-3 text-caption leading-normal text-muted-foreground">
        These findings were decided from the Enterprise-CA host&rsquo;s own registry — each one
        needed the CA host hive and is not derivable from ntds.dit alone.
      </p>
      <ul className="space-y-2">
        {findings.map((f) => {
          const { badge, tone } = caFindingDisplay(f);
          const prov = f.provenance;
          return (
            <li
              key={f.prop}
              className={cn(
                "rounded-md border p-3",
                tone === "risk" ? "border-degraded/40 bg-degraded/5" : "border-border bg-surface-raised/50",
              )}
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-body-sm font-medium leading-snug text-foreground">{f.title}</span>
                <Badge variant={tone === "risk" ? "degraded" : "outline"}>{badge}</Badge>
              </div>
              <p className="mt-1.5 break-anywhere text-caption leading-normal text-muted-foreground">
                {f.caption}
              </p>
              {prov.source_file || prov.image_sha256 ? (
                <p className="mt-2 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-micro text-muted-foreground">
                  <FileKey2 className="size-3 shrink-0" />
                  <span>from CA host hive</span>
                  {prov.source_file ? (
                    <span className="break-anywhere font-mono">· {prov.source_file}</span>
                  ) : null}
                  {prov.image_sha256 ? (
                    <span className="font-mono tabular-nums" title={prov.image_sha256}>
                      · sha {shortSha(prov.image_sha256)}
                    </span>
                  ) : null}
                </p>
              ) : null}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

/** The full guided dossier (doc 10 §5 / doc 21). Shared by the app page + print. */
export function DossierBody({ caseId, dossier, glossary, includePaths = true, variant = "screen" }: Props) {
  const d = dossier;
  const { resolvedTheme } = useTheme();
  const badges = uacBadges(d);
  const isGroup = d.kind === "Group";
  const members = d.group_members ?? [];
  const directIds = useMemo(
    () => new Set(d.inbound_edges.filter((e) => e.kind === "MemberOf").map((e) => e.other.node_id)),
    [d.inbound_edges],
  );

  const flagRows: Array<{ key: string; caption: string | null }> = [
    ...Object.entries(d.node_flags)
      .filter(([, v]) => v)
      .map(([k]) => ({ key: k, caption: flagCaption(glossary, k) })),
  ];
  if (d.uac?.reversible_password) {
    flagRows.push({ key: "reversible_password", caption: flagCaption(glossary, "reversible_password") });
  }

  // At-a-glance counts (the "shape" before the operator reads).
  const controlsCount = new Set(d.outbound_edges.map((e) => e.other.node_id)).size;
  const controllerCount = groupInboundByController(d.inbound_edges).length;
  const tier0Hops = d.risk?.tier0_hops;

  const headerCls =
    variant === "screen"
      ? "dossier-section sticky top-0 z-20 -mx-4 border-b border-border bg-surface/95 px-4 py-3 backdrop-blur sm:-mx-6 sm:px-6 print:static print:mx-0 print:bg-transparent print:px-0 print:backdrop-blur-none"
      : "dossier-section border-b border-border pb-3";

  return (
    <article className="dossier-entity space-y-5">
      {/* 1. Sticky identity header */}
      <header className={headerCls}>
        <div className="flex flex-wrap items-center gap-2">
          <span className="size-3 rounded-full" style={{ backgroundColor: kindColor(d.kind, resolvedTheme) }} />
          <h1 className="text-display leading-7 tracking-tight">{d.label}</h1>
          <Badge variant="outline">{d.kind}</Badge>
          {d.risk?.tier === 0 ? <Badge variant="tier0">Tier-0</Badge> : null}
          {badges.map((b) => (
            <Badge key={b} variant={b === "disabled" ? "default" : "degraded"}>
              {b}
            </Badge>
          ))}
          {d.risk ? (
            <Badge variant="accent" className="ml-auto gap-1">
              <ShieldAlert className="size-3" /> risk {d.risk.score}
            </Badge>
          ) : null}
        </div>
      </header>

      {/* Briefing — pinned directly under identity */}
      {d.exec_summary && d.exec_summary.length > 0 ? (
        <section className="dossier-section rounded-lg border border-accent/30 bg-accent/5 p-5 elevated sm:p-6">
          <h2 className="eyebrow mb-2 text-accent">Briefing</h2>
          <div className="space-y-2">
            {d.exec_summary.map((s, i) => (
              <p key={i} className="text-body leading-relaxed text-foreground-secondary">
                {s}
              </p>
            ))}
          </div>
        </section>
      ) : null}

      {/* Multi-source divergence overlay — pinned high so a contested value is
          never missed (only present on a folded, merged case view). */}
      {d.merge ? <MergeOverlaySection merge={d.merge} /> : null}

      {/* At-a-glance stat strip */}
      <div className="dossier-section flex flex-wrap gap-2">
        {tier0Hops !== null && tier0Hops !== undefined ? (
          <Stat value={tier0Hops} label={`hop${tier0Hops === 1 ? "" : "s"} to Tier-0`} tone="tier0" />
        ) : null}
        <Stat value={controlsCount} label="objects controlled" tone={controlsCount > 0 ? "accent" : undefined} />
        <Stat value={controllerCount} label="controlled by" />
        <Stat value={d.group_memberships.length} label="group memberships" />
        {isGroup ? <Stat value={members.length} label="members" /> : null}
      </div>

      {/* Two-column body: narrative (main) · reference (side) */}
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_320px] print:block print:space-y-4">
        {/* ── Narrative main ── */}
        <div className="space-y-5">
          {/* CA-host configuration — high-signal, pinned above relationships on an
              EnterpriseCA / CA host Computer (absent/empty on every other node). */}
          {d.ca_node_findings && d.ca_node_findings.length > 0 ? (
            <CaFindingsSection findings={d.ca_node_findings} />
          ) : null}

          {isGroup ? (
            <Card title="Members — who is in this group">
              <div className="mb-2 flex items-center gap-1.5 text-caption text-muted-foreground">
                <Users className="size-3.5" />
                <span>Effective membership (nested + primary-group folded in).</span>
              </div>
              <GroupMembers members={members} directIds={directIds} caseId={caseId} variant={variant} resolved={resolvedTheme} />
            </Card>
          ) : null}

          <Card title="Who controls this (inbound ACEs)">
            <InboundAces edges={d.inbound_edges} caseId={caseId} glossary={glossary} selfKind={d.kind} variant={variant} />
          </Card>

          <Card title="What this controls (outbound)">
            <OutboundControl edges={d.outbound_edges} caseId={caseId} glossary={glossary} selfKind={d.kind} variant={variant} />
          </Card>

          <Card title="Member of — groups this belongs to">
            {d.group_memberships.length === 0 ? (
              <p className="text-caption text-muted-foreground">Not a member of any group.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {d.group_memberships.map((g) => (
                  <span key={g.node_id} className="inline-flex items-center gap-1">
                    {variant === "screen" ? (
                      <Link
                        to={`/case/${encodeURIComponent(caseId)}/dossier/${encodeURIComponent(g.node_id)}`}
                        title="Inherits this group's rights"
                        className="rounded border border-border px-2 py-0.5 font-mono text-caption text-accent hover:border-border-strong"
                      >
                        {g.label}
                      </Link>
                    ) : (
                      <span className="rounded border border-border px-2 py-0.5 font-mono text-caption text-foreground">{g.label}</span>
                    )}
                    {g.is_tier0 ? <Badge variant="tier0">Tier-0</Badge> : null}
                  </span>
                ))}
              </div>
            )}
            <p className="mt-2 text-caption text-muted-foreground">Inherits every right these groups hold, transitively.</p>
          </Card>

          {includePaths ? (
            <>
              <Card title="Paths to Tier-0 (from here)">
                <PathSection caseId={caseId} nodeId={d.node_id} direction="outbound" print={variant === "print"} />
              </Card>
              <Card title="Who can reach this (inbound paths)">
                <PathSection caseId={caseId} nodeId={d.node_id} direction="inbound" print={variant === "print"} />
              </Card>
            </>
          ) : null}
        </div>

        {/* ── Reference side (sticky on wide screens) ── */}
        <aside className="space-y-5 xl:sticky xl:top-20 xl:self-start print:static">
          <Ref title="Identity">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-1">
              <Field label="SID" value={d.object_sid} />
              <Field label="GUID" value={d.object_guid} />
              <Field label="sAMAccountName" value={d.samaccountname} />
              <Field label="UPN" value={d.upn} />
              <Field label="Distinguished name" value={d.distinguished_name} />
              <Field label="Display name" value={d.display_name} />
              <Field label="Description" value={d.description} />
              <Field label="Domain" value={d.domain_fqdn} />
              <Field label="adminCount" value={d.admincount === null ? null : String(d.admincount)} />
              <Field label="primaryGroupID" value={d.primary_group_id === null ? null : String(d.primary_group_id)} />
              <Field label="pwdLastSet" value={ts(d.pwd_last_set)} />
              <Field label="lastLogonTimestamp" value={ts(d.last_logon_timestamp)} />
              <Field label="whenCreated" value={ts(d.when_created)} />
              <Field label="whenChanged" value={ts(d.when_changed)} />
            </div>
          </Ref>

          <Ref title="Flags & attributes">
            <div className="space-y-3">
              {flagRows.length === 0 ? (
                <p className="text-caption text-muted-foreground">No attacker-relevant flags set.</p>
              ) : (
                <ul className="space-y-1.5">
                  {flagRows.map((f) => (
                    <li key={f.key} className="flex flex-col gap-0.5">
                      <Badge variant="degraded" className="w-fit" title={f.caption ?? undefined}>
                        {f.key}
                      </Badge>
                      {f.caption ? <span className="text-caption leading-normal text-muted-foreground">{f.caption}</span> : null}
                    </li>
                  ))}
                </ul>
              )}
              {d.spns.length > 0 ? (
                <div>
                  <span className="eyebrow">SPNs (kerberoast surface)</span>
                  <ul className="mt-1 space-y-1">
                    {d.spns.map((s) => (
                      <li key={s} className="break-anywhere font-mono text-caption leading-normal text-foreground">{s}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
              {d.sid_history.length > 0 ? (
                <div>
                  <span className="eyebrow">SID history</span>
                  <ul className="mt-1 space-y-1">
                    {d.sid_history.map((s) => (
                      <li key={s} className="break-anywhere font-mono text-caption leading-normal text-foreground">{s}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          </Ref>

          <Ref title="Risk">
            {d.risk ? (
              <div className="space-y-2">
                <p className="text-body-sm">
                  Total score <span className="font-mono tabular-nums text-foreground">{d.risk.score}</span>
                  {d.risk.tier0_hops !== null && d.risk.tier0_hops !== undefined ? (
                    <span className="text-muted-foreground">
                      {" "}· reaches Tier-0 in <span className="font-mono tabular-nums text-foreground">{d.risk.tier0_hops}</span> hop
                      {d.risk.tier0_hops === 1 ? "" : "s"}
                    </span>
                  ) : null}
                </p>
                {d.risk.factors.length > 0 ? (
                  <DenseTable>
                    <DenseHead>
                      <DenseTh>Factor</DenseTh>
                      <DenseTh>Detail</DenseTh>
                      <DenseTh numeric>Weight</DenseTh>
                    </DenseHead>
                    <DenseBody>
                      {d.risk.factors.map((f) => (
                        <DenseRow key={f.code}>
                          <DenseCell className="text-caption">{f.label}</DenseCell>
                          <DenseCell className="text-caption text-muted-foreground">{f.detail}</DenseCell>
                          <DenseCell numeric>+{f.weight}</DenseCell>
                        </DenseRow>
                      ))}
                    </DenseBody>
                  </DenseTable>
                ) : null}
              </div>
            ) : (
              <p className="text-caption text-muted-foreground">
                Not risk-scored (risk covers principals + the Domain object).
              </p>
            )}
          </Ref>

          <Ref title="Secrets (redacted references)">
            {d.secret_refs.length === 0 ? (
              <p className="text-caption text-muted-foreground">no secret references</p>
            ) : (
              <ul className="space-y-1">
                {d.secret_refs.map((s, i) => (
                  <li key={s.secret_id ?? i} className="flex flex-wrap items-center gap-2 text-caption">
                    <KeyRound className="size-3 text-muted-foreground" />
                    <span className="font-mono text-foreground">{s.secret_type ?? "secret"}</span>
                    {s.label ? <span className="text-muted-foreground">{s.label}</span> : null}
                    <Badge variant={s.decrypted ? "degraded" : "outline"}>
                      {s.decrypted ? "decrypted ref" : "not decrypted"}
                    </Badge>
                    {s.decryptable_offline ? <Badge variant="outline">offline-decryptable</Badge> : null}
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-2 flex items-center gap-1 text-caption text-muted-foreground">
              <Lock className="size-3" /> Values and hashes are never shown — redacted references only.
            </p>
          </Ref>

          <footer className="dossier-footer dossier-section rounded-md border border-border bg-surface-raised/50 p-4">
            <h2 className="eyebrow mb-3">Provenance</h2>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-1">
              <Field label="Source file" value={d.provenance.source_file} />
              <Field
                label="Image SHA-256"
                value={
                  d.provenance.image_sha256 ? (
                    <span title={d.provenance.image_sha256}>{shortSha(d.provenance.image_sha256)}</span>
                  ) : null
                }
              />
              <Field label="Source object id" value={d.provenance.source_object_id} />
              <Field label="Directory timestamp" value={ts(d.provenance.directory_timestamp)} />
              <Field label="Ingest run" value={d.provenance.ingest_run_id} />
            </div>
          </footer>
        </aside>
      </div>
    </article>
  );
}
