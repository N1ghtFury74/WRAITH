import { CheckCircle2, FileUp, Info, RefreshCw, Upload, X } from "lucide-react";
import { useRef, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { TooltipContent, TooltipProvider, TooltipRoot, TooltipTrigger } from "@/components/ui/tooltip";
import { api, ApiError, type ArtifactKindOut, type ArtifactRegistered } from "@/lib/api";
import { reasonText } from "@/lib/reasons";
import { cn, formatBytes, shortSha } from "@/lib/utils";

/**
 * Per-kind "why this file" help text, sourced from the catalog `unlocks` /
 * coverage `note` model (doc 16 §E). Only the kinds whose value is non-obvious get
 * one; others rely on the always-visible "Unlocks" line. Kept short so the tooltip
 * stays a help affordance, not a wall of text.
 */
const KIND_WHY: Partial<Record<string, string>> = {
  system_hive:
    "The DC SYSTEM hive unlocks three things: its boot key decrypts NTDS secrets " +
    "(credential-material recovery), its cert-mapping registry makes ESC9/ESC10 decidable, " +
    "and it fills the AD CS DC-config plane. Without it those stay undecidable — never 'clean'.",
  sysvol:
    "SYSVOL unlocks Group Policy edges: restricted-group / GPP local-admin, RDP, DCOM and " +
    "PS-Remoting pushes, plus dangerous user-rights assignments on the computers each GPO applies " +
    "to. These edges are inferred — a superset of candidate paths WRAITH cannot RSoP-resolve " +
    "offline (security filtering, WMI filters, enforcement are not evaluated), so they show too " +
    "much, never too little; verify before relying on one.",
  ca_host_registry:
    "Two hives from the Enterprise-CA host, uploaded together. The SYSTEM hive carries the CA's " +
    "Security descriptor + EditFlags — it is what makes ManageCA / ManageCertificates and ESC6 / " +
    "ESC11 / ESC16 decidable (they cannot be derived from ntds.dit alone). The SOFTWARE hive is " +
    "OPTIONAL and adds only the machine-wide DCOM activation posture (ESC7 context). Without the " +
    "CA host hive those CA-role / ESC findings stay undecidable — counted gaps, never 'clean'.",
};

/**
 * Per-kind optional COMPANION hive. One primary artifact can ride a second hive in
 * the same composite upload: `member_sam` takes the host SYSTEM hive (`system_file`),
 * `ca_host_registry` takes the CA host SOFTWARE hive (`software_file`, the DCOM
 * plane). `field` selects the multipart field the API client appends to.
 */
interface CompanionSpec {
  field: "system" | "software";
  /** Short hive name used in the add/change button + staged chip. */
  hive: string;
  /** One-line hint shown when nothing is staged (why it's worth adding). */
  hint: string;
}

const COMPANION: Partial<Record<string, CompanionSpec>> = {
  member_sam: {
    field: "system",
    hive: "SYSTEM",
    hint: "optional, improves host resolution",
  },
  ca_host_registry: {
    field: "software",
    hive: "SOFTWARE",
    hint: "optional — adds machine-wide DCOM posture",
  },
};

/**
 * Kinds that represent a whole DC SOURCE (ntds.dit + its hive) and can therefore
 * carry the per-source `dc_label` / `domain` tags (multi-source contract §1.2).
 * Tags are OPTIONAL — an untagged primary ntds.dit defaults to the `primary-dc`
 * label server-side, so a single-source case is unaffected.
 */
const SOURCE_TAG_KINDS = new Set(["ntds_dit", "additional_dc"]);

interface UploadTileProps {
  caseId: string;
  kind: ArtifactKindOut;
  /** Capability labels this artifact unlocks (resolved from coverage). */
  unlockLabels: string[];
  /** What coverage is lost while this artifact is absent (coverage reasons). */
  lossWhenAbsent: string[];
  onUploaded: () => void;
}

type Phase = "idle" | "uploading" | "done" | "error";

/**
 * One catalog tile (doc 14 §3.3): drag-drop + click upload for one artifact kind.
 * Simple kinds upload immediately on file select/drop; multi/host kinds show a
 * host-label field (+ optional companion SYSTEM for member_sam) and an explicit
 * Upload button. Surfaces per-file progress, the `replaced` state, and typed 4xx
 * reasons inline — never a silent failure.
 */
export function UploadTile({ caseId, kind, unlockLabels, lossWhenAbsent, onUploaded }: UploadTileProps) {
  const needsHost = kind.multi;
  const companion = COMPANION[kind.id];
  const supportsCompanion = Boolean(companion);
  const supportsFqdn = kind.id === "ca_host_registry";
  // A kind STAGES (file chosen, then an explicit Upload) whenever the operator may
  // attach more before sending: a host label, a companion hive, or a CA host FQDN.
  // Simple single-file kinds (ntds/system/sysvol) still upload on select/drop.
  const stages = needsHost || supportsCompanion || supportsFqdn;

  const mainInputRef = useRef<HTMLInputElement>(null);
  const companionInputRef = useRef<HTMLInputElement>(null);

  const [dragOver, setDragOver] = useState(false);
  const [phase, setPhase] = useState<Phase>("idle");
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ArtifactRegistered | null>(null);

  const [hostLabel, setHostLabel] = useState("");
  const [caHostFqdn, setCaHostFqdn] = useState("");
  const [dcLabel, setDcLabel] = useState("");
  const [domain, setDomain] = useState("");
  const [stagedMain, setStagedMain] = useState<File | null>(null);
  const [stagedCompanion, setStagedCompanion] = useState<File | null>(null);

  const required = kind.necessity === "required";
  const whyText = KIND_WHY[kind.id];
  const isSourceKind = SOURCE_TAG_KINDS.has(kind.id);

  async function doUpload(file: File, companionFile: File | null) {
    setPhase("uploading");
    setProgress(0);
    setError(null);
    try {
      const res = await api.uploadArtifact(caseId, {
        kind: kind.id,
        file,
        hostLabel: needsHost || hostLabel ? hostLabel || undefined : undefined,
        systemFile: companion?.field === "system" ? companionFile : undefined,
        softwareFile: companion?.field === "software" ? companionFile : undefined,
        caHostFqdn: supportsFqdn && caHostFqdn.trim() ? caHostFqdn.trim() : undefined,
        dcLabel: isSourceKind && dcLabel.trim() ? dcLabel.trim() : undefined,
        domain: isSourceKind && domain.trim() ? domain.trim() : undefined,
        onProgress: (f) => setProgress(Math.round(f * 100)),
      });
      setResult(res);
      setPhase("done");
      setStagedMain(null);
      setStagedCompanion(null);
      onUploaded();
    } catch (err) {
      const msg = err instanceof ApiError ? reasonText(err.reason) : String(err);
      setError(msg);
      setPhase("error");
    }
  }

  function handleFiles(files: FileList | null) {
    const file = files?.[0];
    if (!file) return;
    if (stages) {
      // Stage; the operator may add a host label / companion hive / FQDN first.
      setStagedMain(file);
      setPhase("idle");
      setError(null);
    } else {
      void doUpload(file, null);
    }
  }

  const uploading = phase === "uploading";
  const canUploadStaged = Boolean(stagedMain) && (!needsHost || hostLabel.trim().length > 0);

  return (
    <div
      className={cn(
        "rounded-lg border bg-surface p-4 transition-colors",
        dragOver ? "border-accent bg-accent/5" : "border-border",
        required ? "ring-1 ring-accent/20" : "",
      )}
      onDragOver={(e) => {
        e.preventDefault();
        if (!uploading) setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragOver(false);
        if (!uploading) handleFiles(e.dataTransfer.files);
      }}
    >
      {/* Header: full-width title (wraps — never clipped), then badges on their
          own baseline-aligned row, then the id. The uploaded tick floats top-right
          and never competes with the title for horizontal space (doc 10 §7). */}
      <div className="mb-2 flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <h3 className="text-body font-semibold leading-snug text-foreground">{kind.label}</h3>
          <div className="mt-1 flex flex-wrap items-center gap-1.5">
            {required ? (
              <Badge variant="required">required</Badge>
            ) : (
              <Badge variant="outline">optional</Badge>
            )}
            {kind.multi ? <Badge variant="default">per host</Badge> : null}
          </div>
          <p className="mt-1 font-mono text-micro text-muted-foreground">{kind.id}</p>
        </div>
        <div className="flex shrink-0 items-start gap-1.5">
          {whyText ? (
            <TooltipProvider delayDuration={150}>
              <TooltipRoot>
                <TooltipTrigger
                  type="button"
                  aria-label={`Why upload ${kind.label}?`}
                  className="rounded p-0.5 text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                >
                  <Info className="size-4" />
                </TooltipTrigger>
                <TooltipContent side="top" className="max-w-[18rem] leading-snug">
                  {whyText}
                </TooltipContent>
              </TooltipRoot>
            </TooltipProvider>
          ) : null}
          {kind.uploaded ? <CheckCircle2 className="mt-0.5 size-5 text-available" /> : null}
        </div>
      </div>

      {/* Unlocks / loss */}
      <div className="mb-3 space-y-1 text-caption">
        {unlockLabels.length > 0 ? (
          <p className="text-muted-foreground">
            <span className="text-foreground/80">Unlocks:</span> {unlockLabels.join("; ")}
          </p>
        ) : null}
        {!kind.uploaded && lossWhenAbsent.length > 0 ? (
          <p className="text-degraded">
            <span className="font-medium">If absent:</span> {lossWhenAbsent.join(" ")}
          </p>
        ) : null}
      </div>

      {/* Per-source tags (multi-source §1.2): optional DC label + domain. Filled
          BEFORE choosing the file so an immediate upload carries them. Optional —
          an untagged ntds.dit defaults to `primary-dc` (single-source unchanged). */}
      {isSourceKind ? (
        <div className="mb-3 space-y-2 rounded-md border border-border/70 bg-surface-raised/40 p-2.5">
          <p className="text-micro leading-snug text-muted-foreground">
            <span className="font-medium text-foreground/80">Tag this DC</span> — optional, for
            multi-source cases. The ntds.dit stays authoritative; a wrong label is surfaced, never
            trusted.
          </p>
          <div className="grid gap-2 sm:grid-cols-2">
            <div className="space-y-1">
              <Label htmlFor={`dclabel-${kind.id}`}>DC label</Label>
              <Input
                id={`dclabel-${kind.id}`}
                value={dcLabel}
                onChange={(e) => setDcLabel(e.target.value)}
                placeholder="DC01-CORP"
                className="h-8 font-mono text-caption"
                disabled={uploading}
                autoComplete="off"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor={`domain-${kind.id}`}>Domain</Label>
              <Input
                id={`domain-${kind.id}`}
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="corp.example.com"
                className="h-8 font-mono text-caption"
                disabled={uploading}
                autoComplete="off"
              />
            </div>
          </div>
        </div>
      ) : null}

      {/* Already-uploaded source files */}
      {kind.uploaded && kind.source_files.length > 0 ? (
        <div className="mb-3 space-y-0.5">
          {kind.source_files.map((sf) => (
            <p key={sf} className="truncate font-mono text-micro text-available/90">
              ✓ {sf}
            </p>
          ))}
        </div>
      ) : null}

      {/* Multi/host form */}
      {needsHost ? (
        <div className="mb-2 space-y-1">
          <Label htmlFor={`host-${kind.id}`}>Host label</Label>
          <Input
            id={`host-${kind.id}`}
            value={hostLabel}
            onChange={(e) => setHostLabel(e.target.value)}
            placeholder="ws01.corp.local"
            className="h-8 font-mono text-caption"
            disabled={uploading}
            autoComplete="off"
          />
        </div>
      ) : null}

      {/* CA host FQDN — OPTIONAL operator assertion that helps correlate the hive to
          its EnterpriseCA object. A wrong value is surfaced as a counted mismatch,
          never silently trusted. */}
      {supportsFqdn ? (
        <div className="mb-2 space-y-1">
          <Label htmlFor={`fqdn-${kind.id}`}>
            CA host FQDN <span className="font-normal text-muted-foreground">— optional</span>
          </Label>
          <Input
            id={`fqdn-${kind.id}`}
            value={caHostFqdn}
            onChange={(e) => setCaHostFqdn(e.target.value)}
            placeholder="ca01.corp.local"
            className="h-8 font-mono text-caption"
            disabled={uploading}
            autoComplete="off"
          />
        </div>
      ) : null}

      {stagedMain ? (
        <p className="mb-2 flex items-center gap-1 truncate text-caption text-muted-foreground">
          <FileUp className="size-3.5" /> {stagedMain.name} ({formatBytes(stagedMain.size)})
        </p>
      ) : null}

      {companion ? (
        <div className="mb-2 flex items-center gap-2 text-caption">
          <Button
            size="sm"
            variant="ghost"
            disabled={uploading}
            onClick={() => companionInputRef.current?.click()}
          >
            {stagedCompanion ? `Change ${companion.hive}` : `+ companion ${companion.hive}`}
          </Button>
          {stagedCompanion ? (
            <span className="truncate text-muted-foreground">
              {stagedCompanion.name}
              <button
                className="ml-1 text-unavailable"
                onClick={() => setStagedCompanion(null)}
                title={`Remove companion ${companion.hive}`}
              >
                <X className="inline size-3" />
              </button>
            </span>
          ) : (
            <span className="text-muted-foreground">{companion.hint}</span>
          )}
        </div>
      ) : null}

      {/* Progress / error */}
      {uploading ? (
        <div className="mb-2 space-y-1">
          <Progress value={progress} />
          <p className="font-mono text-micro text-muted-foreground">{progress}%</p>
        </div>
      ) : null}
      {phase === "error" && error ? (
        <p className="mb-2 rounded border border-unavailable/30 bg-unavailable/5 px-2 py-1 text-caption text-unavailable">
          {error}
        </p>
      ) : null}
      {phase === "done" && result ? (
        <div className="mb-2 rounded border border-available/30 bg-available/5 px-2 py-1 text-caption">
          <p className="flex items-center gap-1 text-available">
            {result.replaced ? <RefreshCw className="size-3" /> : <CheckCircle2 className="size-3" />}
            {result.replaced ? "Replaced" : "Uploaded"} · {formatBytes(result.size_bytes)}
          </p>
          <p className="truncate font-mono text-micro tabular-nums text-muted-foreground" title={result.image_sha256}>
            sha256 {shortSha(result.image_sha256)}
          </p>
        </div>
      ) : null}

      {/* Actions */}
      <div className="flex gap-2">
        <input
          ref={mainInputRef}
          type="file"
          className="hidden"
          onChange={(e) => handleFiles(e.target.files)}
        />
        <input
          ref={companionInputRef}
          type="file"
          className="hidden"
          onChange={(e) => setStagedCompanion(e.target.files?.[0] ?? null)}
        />
        <Button
          size="sm"
          variant={kind.uploaded ? "secondary" : "default"}
          disabled={uploading}
          onClick={() => mainInputRef.current?.click()}
          className="flex-1"
        >
          <Upload className="size-4" />
          {kind.uploaded ? "Replace file" : needsHost ? "Choose file" : "Choose / drop file"}
        </Button>
        {stages && stagedMain ? (
          <Button
            size="sm"
            disabled={!canUploadStaged || uploading}
            onClick={() => void doUpload(stagedMain, stagedCompanion)}
          >
            Upload
          </Button>
        ) : null}
      </div>
    </div>
  );
}
