import {
  CheckCircle2,
  FolderOpen,
  Loader2,
  SkipForward,
  TriangleAlert,
  Upload,
  X,
} from "lucide-react";
import { useRef, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, ApiError, KIND_LABELS, type ArtifactKindId } from "@/lib/api";
import {
  buildIngestPlan,
  filesFromDrop,
  filesFromInput,
  type PlanRow,
} from "@/lib/folderIngest";
import { reasonText } from "@/lib/reasons";
import { buildSysvolZip, SysvolZipError } from "@/lib/sysvolZip";
import { cn, slugHostLabel } from "@/lib/utils";

type Phase = "idle" | "classifying" | "preview" | "uploading" | "done";
type UploadState = { status: "pending" | "uploading" | "done" | "error"; progress: number; error?: string };

const KIND_OPTIONS: Array<{ value: ArtifactKindId | "skip"; label: string }> = [
  ...(Object.keys(KIND_LABELS) as ArtifactKindId[]).map((id) => ({ value: id, label: KIND_LABELS[id] })),
  { value: "skip", label: "— skip —" },
];

const REASON_TEXT: Record<string, string> = {
  additional_dc_reserved: "extra NTDS — multi-DC merge not wired",
  duplicate_system_hive: "duplicate SYSTEM hive",
  duplicate_member_sam: "duplicate SAM for this host",
  duplicate_sysvol: "duplicate SYSVOL subtree",
  no_consuming_slot: "no consuming slot for this hive",
  no_consuming_slot_on_dc: "DC SAM/SECURITY/SOFTWARE has no consuming slot",
  hive_without_role: "hive with no DC/member role",
  unlabeled_hive: "could not identify hive — override to place",
  unrecognized: "unrecognized file",
  ese_work_file: "ESE work file, not a DIT",
  unrouted_zip: "pre-made zip not auto-routed",
  sysvol_too_large: "SYSVOL exceeds the extraction caps",
  manual_skip: "skipped by operator",
};

function reasonLabel(reason?: string): string {
  if (!reason) return "";
  if (reason.startsWith("exceeds_cap:")) return "exceeds size cap";
  return REASON_TEXT[reason] ?? reason;
}

function isUploadable(row: PlanRow): boolean {
  if (row.status !== "ready" && row.status !== "needs-host-label") return false;
  if (!row.kind) return false;
  if (row.kind === "member_sam" && !row.hostLabel) return false;
  return true;
}

interface Props {
  caseId: string;
  onUploaded: () => void;
}

/** Folder auto-ingest panel (design §1 / §4): pick/drop → classify → preview → upload. */
export function FolderIngest({ caseId, onUploaded }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [dragOver, setDragOver] = useState(false);
  const [rows, setRows] = useState<PlanRow[]>([]);
  const [uploads, setUploads] = useState<Record<string, UploadState>>({});
  const [error, setError] = useState<string | null>(null);

  async function classify(picked: Awaited<ReturnType<typeof filesFromDrop>>) {
    if (picked.length === 0) {
      setError("No files found in that folder.");
      return;
    }
    setPhase("classifying");
    setError(null);
    try {
      const plan = await buildIngestPlan(picked);
      setRows(plan.rows);
      setUploads({});
      setPhase("preview");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setPhase("idle");
    }
  }

  function updateRow(key: string, patch: Partial<PlanRow>) {
    setRows((rs) =>
      rs.map((r) => {
        if (r.key !== key) return r;
        const next = { ...r, ...patch };
        // Recompute status on override/host-label edits.
        if (next.kind === null) {
          next.status = "skipped";
          next.reason = "manual_skip";
        } else if (next.kind === "member_sam") {
          next.status = next.hostLabel ? "ready" : "needs-host-label";
          next.reason = undefined;
        } else if (next.status === "skipped" || next.status === "needs-host-label") {
          next.status = "ready";
          next.reason = undefined;
        }
        return next;
      }),
    );
  }

  async function ingest() {
    setPhase("uploading");
    const targets = rows.filter(isUploadable);
    for (const row of targets) {
      setUploads((u) => ({ ...u, [row.key]: { status: "uploading", progress: 0 } }));
      try {
        let file = row.file;
        if (row.kind === "sysvol" && row.sysvol) {
          file = await buildSysvolZip(row.sysvol.files, row.sysvol.domain);
        }
        if (!file || !row.kind) continue;
        await api.uploadArtifact(caseId, {
          kind: row.kind,
          file,
          hostLabel: row.kind === "member_sam" ? row.hostLabel : undefined,
          systemFile: row.kind === "member_sam" ? row.companion : undefined,
          onProgress: (f) =>
            setUploads((u) => ({ ...u, [row.key]: { status: "uploading", progress: Math.round(f * 100) } })),
        });
        setUploads((u) => ({ ...u, [row.key]: { status: "done", progress: 100 } }));
      } catch (err) {
        const msg =
          err instanceof ApiError
            ? reasonText(err.reason)
            : err instanceof SysvolZipError
              ? reasonLabel(err.reason)
              : String(err);
        setUploads((u) => ({ ...u, [row.key]: { status: "error", progress: 0, error: msg } }));
      }
    }
    setPhase("done");
    onUploaded();
  }

  function reset() {
    setRows([]);
    setUploads({});
    setPhase("idle");
    setError(null);
    if (inputRef.current) inputRef.current.value = "";
  }

  const uploadableCount = rows.filter(isUploadable).length;
  const busy = phase === "uploading" || phase === "classifying";

  return (
    <div className="space-y-3">
      {/* Pick / drop zone */}
      <div
        className={cn(
          "flex flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed p-6 text-center transition-colors duration-150",
          dragOver ? "border-accent bg-accent/5" : "border-border",
        )}
        onDragOver={(e) => {
          e.preventDefault();
          if (!busy) setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          if (!busy && e.dataTransfer.items.length) void (async () => classify(await filesFromDrop(e.dataTransfer.items)))();
        }}
      >
        <FolderOpen className="size-7 text-accent" />
        <p className="text-body font-medium text-foreground">Add an evidence folder</p>
        <p className="max-w-md text-caption text-muted-foreground">
          Point WRAITH at a capture folder — it finds the NTDS database, DC SYSTEM hive, member
          SAMs and SYSVOL, and routes each automatically. Drop it here or select it.
        </p>
        <input
          ref={inputRef}
          type="file"
          /* webkitdirectory is non-standard; set via ref-friendly attributes */
          // @ts-expect-error webkitdirectory is a non-standard input attribute
          webkitdirectory=""
          directory=""
          multiple
          className="hidden"
          onChange={(e) => {
            if (e.target.files) void classify(filesFromInput(e.target.files));
          }}
        />
        <Button size="sm" className="mt-1" disabled={busy} onClick={() => inputRef.current?.click()}>
          {phase === "classifying" ? <Loader2 className="size-4 animate-spin" /> : <FolderOpen className="size-4" />}
          Select evidence folder
        </Button>
      </div>

      {error ? <p className="text-caption text-unavailable">{error}</p> : null}

      {/* Preview table */}
      {rows.length > 0 ? (
        <div className="overflow-hidden rounded-lg border border-border">
          <div className="flex items-center justify-between border-b border-border bg-surface-raised/50 px-3 py-2">
            <span className="eyebrow">Detected {rows.length} items</span>
            <div className="flex items-center gap-2">
              <Button size="sm" variant="ghost" disabled={busy} onClick={reset}>
                <X className="size-3.5" /> Clear
              </Button>
              <Button size="sm" disabled={busy || uploadableCount === 0} onClick={() => void ingest()}>
                {phase === "uploading" ? <Loader2 className="size-4 animate-spin" /> : <Upload className="size-4" />}
                Ingest {uploadableCount} item{uploadableCount === 1 ? "" : "s"}
              </Button>
            </div>
          </div>
          <div className="max-h-80 overflow-y-auto">
            <table className="w-full text-left text-caption">
              <thead className="sticky top-0 bg-surface text-muted-foreground">
                <tr>
                  <th className="px-3 py-1.5 font-medium">Source</th>
                  <th className="px-3 py-1.5 font-medium">Routes to</th>
                  <th className="px-3 py-1.5 font-medium">Host label</th>
                  <th className="px-3 py-1.5 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <Row
                    key={row.key}
                    row={row}
                    upload={uploads[row.key]}
                    disabled={busy}
                    onKind={(kind) => updateRow(row.key, { kind: kind === "skip" ? null : kind })}
                    onHost={(hostLabel) => updateRow(row.key, { hostLabel })}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function statusBadge(row: PlanRow, upload?: UploadState) {
  if (upload?.status === "uploading")
    return (
      <Badge variant="accent" className="gap-1">
        <Loader2 className="size-2.5 animate-spin" /> {upload.progress}%
      </Badge>
    );
  if (upload?.status === "done")
    return (
      <Badge variant="available" className="gap-1">
        <CheckCircle2 className="size-2.5" /> uploaded
      </Badge>
    );
  if (upload?.status === "error")
    return (
      <Badge variant="unavailable" className="gap-1">
        <TriangleAlert className="size-2.5" /> {upload.error ?? "error"}
      </Badge>
    );
  if (row.status === "ready") return <Badge variant="accent">ready</Badge>;
  if (row.status === "needs-host-label") return <Badge variant="degraded">needs host label</Badge>;
  if (row.status === "duplicate")
    return <Badge variant="outline">duplicate</Badge>;
  return (
    <Badge variant="outline" className="gap-1">
      <SkipForward className="size-2.5" /> skipped
    </Badge>
  );
}

function Row({
  row,
  upload,
  disabled,
  onKind,
  onHost,
}: {
  row: PlanRow;
  upload?: UploadState;
  disabled: boolean;
  onKind: (kind: ArtifactKindId | "skip") => void;
  onHost: (hostLabel: string) => void;
}) {
  const skipped = row.status === "skipped" || row.status === "duplicate";
  return (
    <tr className="border-t border-border/60 align-top">
      <td className="max-w-[18rem] px-3 py-2">
        <span className="block truncate font-mono text-micro text-foreground" title={row.source}>
          {row.source}
        </span>
        {skipped && row.reason ? (
          <span className="text-micro text-muted-foreground">{reasonLabel(row.reason)}</span>
        ) : null}
      </td>
      <td className="px-3 py-2">
        {row.overridable ? (
          <select
            disabled={disabled}
            value={row.kind ?? "skip"}
            onChange={(e) => onKind(e.target.value as ArtifactKindId | "skip")}
            className="h-7 rounded border border-input bg-surface-raised px-1.5 text-micro text-foreground focus-visible:border-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {KIND_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        ) : (
          <span className="text-body-sm text-foreground">{row.kind ? KIND_LABELS[row.kind] : "—"}</span>
        )}
      </td>
      <td className="px-3 py-2">
        {row.kind === "member_sam" ? (
          <Input
            value={row.hostLabel ?? ""}
            disabled={disabled}
            placeholder="host"
            onChange={(e) => onHost(slugHostLabel(e.target.value))}
            className="h-7 w-28 font-mono text-micro"
          />
        ) : (
          <span className="text-muted-foreground">—</span>
        )}
      </td>
      <td className="px-3 py-2">{statusBadge(row, upload)}</td>
    </tr>
  );
}
