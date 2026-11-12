import { useQuery } from "@tanstack/react-query";
import { ExternalLink, FileText, ShieldAlert, X } from "lucide-react";
import { Link } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { api, type NodeDossier } from "@/lib/api";
import { errorText } from "@/lib/reasons";
import { kindColor } from "@/lib/graph/encoding";
import { shortSha } from "@/lib/utils";

function Field({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="flex flex-col gap-1">
      <span className="eyebrow">{label}</span>
      {/* mono value sits one step below the sans value (caption vs body-sm) so the
          two read as the same optical size beside the eyebrow label (TYPE CONTRACT). */}
      <span
        className={
          mono
            ? "break-all font-mono text-caption tabular-nums text-foreground"
            : "text-body-sm text-foreground"
        }
      >
        {value}
      </span>
    </div>
  );
}

function uacBadges(d: NodeDossier): string[] {
  const u = d.uac;
  if (!u) return [];
  const out: string[] = [];
  if (u.enabled === false || u.account_disabled) out.push("disabled");
  if (u.enabled === true && !u.account_disabled) out.push("enabled");
  if (u.trusted_for_delegation) out.push("unconstrained deleg");
  if (u.trusted_to_auth_for_delegation) out.push("constrained deleg");
  if (u.dont_require_preauth) out.push("AS-REP roastable");
  if (u.password_not_required) out.push("pwd not required");
  if (u.dont_expire_password) out.push("pwd never expires");
  return out;
}

function topKinds(counts: Record<string, number>, n = 6): Array<[string, number]> {
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, n);
}

/** Right-hand compact inspector for the selected node (full dossier page = FE-3). */
export function Inspector({
  caseId,
  nodeId,
  onClose,
}: {
  caseId: string;
  nodeId: string;
  onClose: () => void;
}) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["node", caseId, nodeId],
    queryFn: () => api.node(caseId, nodeId),
  });

  return (
    <aside className="flex w-80 shrink-0 flex-col overflow-y-auto border-l border-border bg-surface">
      <header className="flex items-center justify-between border-b border-border p-3">
        <span className="eyebrow">Inspector</span>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
          <X className="size-4" />
        </button>
      </header>

      {isLoading ? (
        <LoadingState label="Loading node…" />
      ) : error ? (
        <div className="p-3">
          <ErrorState message={errorText(error)} />
        </div>
      ) : data ? (
        <div className="space-y-4 p-3">
          <div>
            <div className="flex items-center gap-2">
              <span
                className="size-3 rounded-full"
                style={{ backgroundColor: data.provenance ? kindColor(data.kind) : undefined }}
              />
              <span className="text-body font-semibold">{data.label}</span>
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-1.5">
              <Badge variant="outline">{data.kind}</Badge>
              {data.risk && data.risk.tier === 0 ? <Badge variant="unavailable">Tier-0</Badge> : null}
              {uacBadges(data).map((b) => (
                <Badge key={b} variant={b === "disabled" ? "default" : "degraded"}>
                  {b}
                </Badge>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <Field label="SID" value={data.object_sid} mono />
            <Field label="sAMAccountName" value={data.samaccountname} mono />
            <Field label="UPN" value={data.upn} mono />
            <Field label="Distinguished name" value={data.distinguished_name} mono />
            {data.spns.length > 0 ? (
              <Field label="SPNs" value={`${data.spns.length} (kerberoastable surface)`} />
            ) : null}
            {data.sid_history.length > 0 ? (
              <Field label="SID history" value={`${data.sid_history.length} entries`} />
            ) : null}
          </div>

          {data.risk ? (
            <div className="rounded border border-border bg-surface-raised/50 p-2">
              <div className="flex items-center gap-2 text-body-sm">
                <ShieldAlert className="size-3.5 text-degraded" />
                <span className="font-medium">Risk score</span>
                <span className="ml-auto font-mono text-body-sm tabular-nums">{data.risk.score}</span>
              </div>
              {data.risk.factors.length > 0 ? (
                <ul className="mt-1 space-y-1">
                  {data.risk.factors.slice(0, 5).map((f) => (
                    <li key={f.code} className="flex justify-between text-micro text-muted-foreground">
                      <span className="truncate">{f.label}</span>
                      <span className="ml-2 font-mono tabular-nums">+{f.weight}</span>
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <p className="eyebrow mb-1">Inbound edges</p>
              <ul className="space-y-1">
                {topKinds(data.inbound_edge_counts).map(([k, c]) => (
                  <li key={k} className="flex justify-between text-micro">
                    <span className="truncate font-mono text-muted-foreground">{k}</span>
                    <span className="ml-2 font-mono tabular-nums">{c}</span>
                  </li>
                ))}
                {Object.keys(data.inbound_edge_counts).length === 0 ? (
                  <li className="text-micro text-muted-foreground">none</li>
                ) : null}
              </ul>
            </div>
            <div>
              <p className="eyebrow mb-1">Outbound edges</p>
              <ul className="space-y-1">
                {topKinds(data.outbound_edge_counts).map(([k, c]) => (
                  <li key={k} className="flex justify-between text-micro">
                    <span className="truncate font-mono text-muted-foreground">{k}</span>
                    <span className="ml-2 font-mono tabular-nums">{c}</span>
                  </li>
                ))}
                {Object.keys(data.outbound_edge_counts).length === 0 ? (
                  <li className="text-micro text-muted-foreground">none</li>
                ) : null}
              </ul>
            </div>
          </div>

          {data.group_memberships.length > 0 ? (
            <Field label="Group memberships" value={`${data.group_memberships.length} groups`} />
          ) : null}

          {/* Provenance (the WRAITH non-negotiable) */}
          <div className="rounded border border-border bg-surface-raised/40 p-2">
            <p className="eyebrow mb-1">Provenance</p>
            <div className="space-y-1">
              <Field label="Source file" value={data.provenance.source_file} mono />
              <Field
                label="Image SHA-256"
                value={
                  data.provenance.image_sha256 ? (
                    <span title={data.provenance.image_sha256}>{shortSha(data.provenance.image_sha256)}</span>
                  ) : null
                }
                mono
              />
              <Field label="Source object id" value={data.provenance.source_object_id} mono />
              <Field
                label="Directory timestamp"
                value={data.provenance.directory_timestamp}
                mono
              />
            </div>
          </div>

          <Button asChild variant="secondary" size="sm" className="w-full">
            <Link to={`/case/${encodeURIComponent(caseId)}/dossier/${encodeURIComponent(data.node_id)}`}>
              <FileText className="size-4" /> View full dossier
              <ExternalLink className="size-3 opacity-60" />
            </Link>
          </Button>
        </div>
      ) : null}
    </aside>
  );
}
