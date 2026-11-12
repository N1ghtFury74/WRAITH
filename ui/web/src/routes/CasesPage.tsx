import { useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, FolderPlus, Link2, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { DeleteCaseDialog } from "@/components/case/DeleteCaseDialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/states";
import { useCaseList } from "@/hooks/useCaseList";
import {
  api,
  ApiError,
  type CaseListItem,
  type DcCardinality,
  type DomainCardinality,
} from "@/lib/api";
import { errorText } from "@/lib/reasons";
import { cn, formatDate, slugifyCaseId } from "@/lib/utils";
import { useCasesStore } from "@/store/cases";

/** Short display label for an uploaded artifact kind chip. */
const KIND_SHORT: Record<string, string> = {
  ntds_dit: "NTDS",
  system_hive: "SYSTEM",
  sysvol: "SYSVOL",
  member_sam: "SAM",
  ca_host_registry: "CA",
  additional_dc: "+DC",
};

/** Route a selected case to its most useful view: graph if analyzed, else ingest. */
function destFor(c: Pick<CaseListItem, "case_id" | "analyzed">): string {
  return `/case/${encodeURIComponent(c.case_id)}/${c.analyzed ? "graph" : "ingest"}`;
}

export function CasesPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const addCase = useCasesStore((s) => s.addCase);
  const removeCase = useCasesStore((s) => s.removeCase);
  const casesQuery = useCaseList();
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [operator, setOperator] = useState("");
  const [authRef, setAuthRef] = useState("");
  const [domainCardinality, setDomainCardinality] = useState<DomainCardinality>("single_domain");
  const [dcCardinality, setDcCardinality] = useState<DcCardinality>("single_dc");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [attachId, setAttachId] = useState("");
  const [attachBusy, setAttachBusy] = useState(false);
  const [attachError, setAttachError] = useState<string | null>(null);

  const derivedId = useMemo(() => slugifyCaseId(name), [name]);

  function refreshList() {
    void queryClient.invalidateQueries({ queryKey: ["cases"] });
  }

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!derivedId) {
      setError("Enter a name with at least one letter or number.");
      return;
    }
    if (!operator.trim()) {
      setError("Operator is required.");
      return;
    }
    setBusy(true);
    try {
      const created = await api.createCase({
        case_id: derivedId,
        operator: operator.trim(),
        authorization_ref: authRef.trim() || null,
        domain_cardinality: domainCardinality,
        dc_cardinality: dcCardinality,
      });
      addCase({ caseId: created.case_id, operator: created.operator, createdAt: created.created_at });
      refreshList();
      navigate(`/case/${encodeURIComponent(created.case_id)}/ingest`);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  async function onAttach(e: React.FormEvent) {
    e.preventDefault();
    setAttachError(null);
    const id = attachId.trim();
    if (!id) return;
    setAttachBusy(true);
    try {
      await api.catalog(id); // 404 => unknown case on disk
      addCase({ caseId: id, operator: null, createdAt: null });
      refreshList();
      navigate(`/case/${encodeURIComponent(id)}/ingest`);
    } catch (err) {
      setAttachError(
        err instanceof ApiError && err.status === 404 ? "No such case on disk." : errorText(err),
      );
    } finally {
      setAttachBusy(false);
    }
  }

  const cases = casesQuery.data ?? [];

  return (
    <div className="mx-auto max-w-5xl p-4 sm:p-5">
      <div className="mb-5">
        <h1 className="text-display">Cases</h1>
        <p className="text-body text-muted-foreground">
          A case is one environment you are hunting in — an isolated, offline workspace for a single
          set of dead-disk DC artifacts. Open one to map its privilege terrain, or create a new one.
          Everything (upload, analyze, graph) runs offline from here.
        </p>
      </div>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
        {/* Create + attach */}
        <div className="space-y-5">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FolderPlus className="size-4 text-accent" /> New case
              </CardTitle>
              <CardDescription>Type any friendly name — we derive a safe id.</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={onCreate} className="space-y-3">
                <div className="space-y-1">
                  <Label htmlFor="case-name">Case name</Label>
                  <Input
                    id="case-name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Test 1"
                    autoComplete="off"
                  />
                  {name.trim() ? (
                    derivedId ? (
                      <p className="text-caption text-muted-foreground">
                        will be created as <span className="font-mono text-accent">{derivedId}</span>
                      </p>
                    ) : (
                      <p className="text-caption text-unavailable">
                        needs at least one letter or number
                      </p>
                    )
                  ) : null}
                </div>
                <div className="space-y-1">
                  <Label htmlFor="operator">Operator</Label>
                  <Input
                    id="operator"
                    value={operator}
                    onChange={(e) => setOperator(e.target.value)}
                    placeholder="analyst name or handle"
                    autoComplete="off"
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="auth-ref">Authorization ref (optional)</Label>
                  <Input
                    id="auth-ref"
                    value={authRef}
                    onChange={(e) => setAuthRef(e.target.value)}
                    placeholder="e.g. ENG-4291"
                    autoComplete="off"
                  />
                </div>
                <CaseShapePicker
                  domainCardinality={domainCardinality}
                  dcCardinality={dcCardinality}
                  onDomainChange={setDomainCardinality}
                  onDcChange={setDcCardinality}
                />
                {error ? <p className="text-caption text-unavailable">{error}</p> : null}
                <Button type="submit" disabled={busy || !derivedId} className="w-full">
                  {busy ? "Creating…" : "Create case"}
                </Button>
              </form>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Link2 className="size-4 text-accent" /> Attach by id
              </CardTitle>
              <CardDescription>Open a specific workspace directly by its id.</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={onAttach} className="flex gap-2">
                <Input
                  value={attachId}
                  onChange={(e) => setAttachId(e.target.value)}
                  placeholder="case-id"
                  className="font-mono"
                  autoComplete="off"
                />
                <Button type="submit" variant="secondary" disabled={attachBusy}>
                  {attachBusy ? "…" : "Attach"}
                </Button>
              </form>
              {attachError ? <p className="mt-2 text-caption text-unavailable">{attachError}</p> : null}
            </CardContent>
          </Card>
        </div>

        {/* Server-authoritative case list */}
        <Card>
          <CardHeader>
            <CardTitle>All cases</CardTitle>
            <CardDescription>
              Every environment on this server. Open one to pick up the hunt where you left off.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {casesQuery.isLoading ? (
              <SkeletonRows rows={4} className="py-2" />
            ) : casesQuery.error ? (
              <ErrorState
                message={errorText(casesQuery.error)}
                action={
                  <Button size="sm" variant="secondary" onClick={() => refreshList()}>
                    Retry
                  </Button>
                }
              />
            ) : cases.length === 0 ? (
              <EmptyState title="No cases yet" hint="Create your first case on the left." />
            ) : (
              <ul className="divide-y divide-border">
                {cases.map((c) => (
                  <li key={c.case_id} className="flex items-center gap-2">
                    <button
                      onClick={() => {
                        addCase({ caseId: c.case_id, operator: c.operator, createdAt: c.created_at });
                        navigate(destFor(c));
                      }}
                      className="flex min-w-0 flex-1 items-center gap-3 py-3 text-left transition-colors hover:bg-surface-raised/40"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="truncate font-mono text-body-sm text-foreground">{c.case_id}</span>
                          {c.unreadable ? (
                            <Badge variant="unavailable" className="gap-1">
                              <AlertTriangle className="size-2.5" /> unreadable
                            </Badge>
                          ) : c.analyzed ? (
                            <Badge variant="available" className="gap-1">
                              <CheckCircle2 className="size-2.5" /> analyzed
                            </Badge>
                          ) : (
                            <Badge variant="outline">not analyzed</Badge>
                          )}
                        </div>
                        <div className="mt-0.5 flex items-center gap-2 text-caption text-muted-foreground">
                          {c.operator ? <span className="truncate">{c.operator}</span> : null}
                          <span className="tabular-nums text-muted-foreground">{formatDate(c.created_at)}</span>
                        </div>
                        {c.uploaded_kinds.length > 0 ? (
                          <div className="mt-1 flex flex-wrap gap-1">
                            {c.uploaded_kinds.map((k) => (
                              <span
                                key={k}
                                className="rounded bg-muted px-1.5 py-0.5 font-mono text-micro text-muted-foreground"
                              >
                                {KIND_SHORT[k] ?? k}
                              </span>
                            ))}
                          </div>
                        ) : null}
                      </div>
                      <span className="shrink-0 text-caption text-accent">
                        {c.analyzed ? "Open graph →" : "Open →"}
                      </span>
                    </button>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="shrink-0 text-muted-foreground hover:text-unavailable"
                      title={`Delete ${c.case_id}`}
                      onClick={() => setDeleteTarget(c.case_id)}
                    >
                      <Trash2 className="size-4" />
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      <DeleteCaseDialog
        caseId={deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onDeleted={(id) => {
          setDeleteTarget(null);
          removeCase(id);
          void queryClient.invalidateQueries({ queryKey: ["cases"] });
        }}
      />
    </div>
  );
}

/** One two-choice segmented control (axis of the case-shape picker). */
function AxisToggle<T extends string>({
  options,
  value,
  onChange,
}: {
  options: ReadonlyArray<{ value: T; label: string }>;
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div className="inline-flex rounded-md border border-border bg-surface-raised/60 p-0.5" role="group">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={value === o.value}
          onClick={() => onChange(o.value)}
          className={cn(
            "rounded px-3 py-1 text-caption font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
            value === o.value
              ? "bg-accent/15 text-accent"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/**
 * Case-shape picker (multi-source contract §1.1): two orthogonal axes declared at
 * case creation. Domain cardinality gates whether cross-domain edge wiring runs;
 * DC cardinality gates whether the opt-in merge/divergence engine is available.
 * The declaration is a WORKFLOW hint — the ingested ntds.dit remains authoritative
 * and any mismatch is surfaced honestly after ingest (never silently corrected).
 */
function CaseShapePicker({
  domainCardinality,
  dcCardinality,
  onDomainChange,
  onDcChange,
}: {
  domainCardinality: DomainCardinality;
  dcCardinality: DcCardinality;
  onDomainChange: (v: DomainCardinality) => void;
  onDcChange: (v: DcCardinality) => void;
}) {
  return (
    <div className="space-y-3 rounded-lg border border-border bg-surface-raised/40 p-3">
      <div className="space-y-1">
        <span className="eyebrow">Case shape</span>
        <p className="text-micro leading-snug text-muted-foreground">
          How many domains and DCs this case holds. You can start with one source and add more on the
          ingest screen — the picker only sets which analyses are offered.
        </p>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <Label className="text-caption text-foreground">Domains</Label>
          <p className="text-micro text-muted-foreground">
            {domainCardinality === "multi_domain"
              ? "Wires cross-domain edges (trusts, FSPs, sIDHistory)."
              : "A single domain — no cross-domain wiring."}
          </p>
        </div>
        <AxisToggle
          value={domainCardinality}
          onChange={onDomainChange}
          options={[
            { value: "single_domain", label: "Single" },
            { value: "multi_domain", label: "Multi-domain" },
          ]}
        />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3">
        <div className="min-w-0">
          <Label className="text-caption text-foreground">DCs per domain</Label>
          <p className="text-micro text-muted-foreground">
            {dcCardinality === "multi_dc"
              ? "Enables the opt-in merge + divergence report across DCs."
              : "One DC per domain — merge is unnecessary."}
          </p>
        </div>
        <AxisToggle
          value={dcCardinality}
          onChange={onDcChange}
          options={[
            { value: "single_dc", label: "Single" },
            { value: "multi_dc", label: "Multi-DC" },
          ]}
        />
      </div>
    </div>
  );
}
