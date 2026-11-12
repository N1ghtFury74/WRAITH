import { ApiError } from "@/lib/api";

/**
 * Map a backend typed `reason` code (wraith/api/ingest.py) to an operator-facing
 * sentence. Upload/zip/case reasons are enumerated; `bad_magic:<kind>` /
 * `too_large:<kind>` carry a `:kind` suffix handled by prefix. Anything unknown
 * falls back to the raw reason so nothing is ever shown as a silent generic
 * failure (honest-gap principle).
 */
const EXACT: Record<string, string> = {
  case_exists: "A case with this id already exists.",
  unsafe_case_id: "That case id is not allowed (unsafe path characters).",
  unknown_case: "No such case on disk.",
  case_not_ready: "The case exists but has not been analyzed yet.",
  case_id_required: "A case must be selected first.",
  host_label_required_for_multi: "This artifact type needs a host label (it can be uploaded per host).",
  unsafe_path: "The upload resolved to an unsafe path and was rejected.",
  upload_index_corrupt: "The case upload index is unreadable — re-create the case or re-upload.",
  zip_slip: "The SYSVOL archive contains an unsafe member path and was rejected.",
  zip_bomb: "The SYSVOL archive exceeds the size/member safety cap.",
  bad_zip: "That file is not a valid zip archive.",
  ntds_dit_required: "NTDS database (ntds.dit) is required before analysis can run.",
  run_in_progress: "An analysis is already running for this case.",
  unknown_run: "That analysis run is no longer tracked.",
  dc_label_not_unique: "That DC label is already used by another source in this case — pick a unique label.",
  unknown_source_ids: "One or more selected sources do not belong to this case.",
  case_config_missing: "The case configuration file is missing.",
  network_error: "Could not reach the WRAITH API (connection error).",
  aborted: "Upload cancelled.",
};

const PREFIX: Array<[string, (kind: string) => string]> = [
  ["bad_magic:", (k) => `File content does not look like a ${describeSniff(k)} — wrong file for this slot?`],
  ["too_large:", (k) => `File exceeds the size cap for a ${describeSniff(k)}.`],
  ["unknown_kind:", (k) => `Unknown artifact kind "${k}".`],
  ["reserved_pass_not_wired:", (k) => `${k} is stored for provenance; its pass is not wired yet.`],
];

function describeSniff(sniff: string): string {
  switch (sniff) {
    case "ese":
      return "NTDS/ESE database";
    case "regf":
      return "Windows registry hive";
    case "zip":
      return "SYSVOL zip archive";
    default:
      return sniff;
  }
}

/** Human message for a typed reason code. */
export function reasonText(reason: string): string {
  if (reason in EXACT) return EXACT[reason];
  for (const [prefix, fn] of PREFIX) {
    if (reason.startsWith(prefix)) return fn(reason.slice(prefix.length));
  }
  return reason;
}

/** Human message for any thrown error (ApiError-aware). */
export function errorText(err: unknown): string {
  if (err instanceof ApiError) return reasonText(err.reason);
  if (err instanceof Error) return err.message;
  return String(err);
}
