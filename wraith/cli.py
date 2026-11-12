"""WRAITH command-line entrypoint (Typer).

Thin command layer only — all logic lives in the packages. Commands:
  * ``case new``   — create a case workspace + ``case.json`` + canonical store.
  * ``ingest``     — hash/copy inputs, write the run manifest + provenance ledger.
  * ``secret init``/``secret put``/``secret reveal`` — the encrypted-store path.

Launch posture (NFR-10): the Docker/CLI entrypoint must run Python in isolated
mode (``python -I -m wraith``) so a planted module in an artifact directory
cannot shadow a stdlib import. The root callback FAILS CLOSED — it refuses to
run unless Python is isolated, with an explicit ``--allow-unisolated`` escape
hatch for development.
"""

from __future__ import annotations

import getpass
import importlib.metadata as importlib_metadata
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from uuid import UUID, uuid4

import typer
from pydantic import SecretBytes

from wraith import WRAITH_VERSION
from wraith.acquisition.ingest import IngestMode, ingest_file
from wraith.case.case import CaseConfig, load_case_config, write_case_config
from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import RunOutputs, write_run_manifest
from wraith.case.workspace import create_workspace, load_workspace
from wraith.export.bloodhound import DEFAULT_INGEST_VERSION, ExportConfig, export_bloodhound
from wraith.export.pipeline import PipelineInputs, SamHostInput, run_analysis_pipeline
from wraith.model.store import open_canonical_store, open_canonical_store_readonly
from wraith.provenance.ledger import write_ledger_rows
from wraith.secrets.keyring import create_keyring, load_keyring, unwrap_dek, write_keyring
from wraith.secrets.records import SecretDecryptError, SecretType
from wraith.secrets.redaction import install_secret_log_filter
from wraith.secrets.store import SecretStore

app = typer.Typer(help="WRAITH — offline Active Directory relationship mapper.")
case_app = typer.Typer(help="Case workspace lifecycle.")
secret_app = typer.Typer(help="Encrypted secret store (redact-by-default).")
export_app = typer.Typer(help="Export the canonical graph to external formats.")
app.add_typer(case_app, name="case")
app.add_typer(secret_app, name="secret")
app.add_typer(export_app, name="export")

_log = logging.getLogger("wraith.cli")

CasesRoot = Annotated[Path, typer.Option(help="Parent directory holding all cases.")]
CaseId = Annotated[str, typer.Option(help="Case id / slug (filesystem-safe).")]

#: Correctness-critical distributions whose resolved versions are recorded in
#: every run manifest + ledger row for reproducibility/provenance (NFR-06).
_CORRECTNESS_CRITICAL_DISTS: tuple[str, ...] = (
    "cryptography",
    "argon2-cffi",
    "duckdb",
    "pydantic",
)


@app.callback()
def _root(
    allow_unisolated: Annotated[
        bool,
        typer.Option(help="Dev-only: allow running without Python -I isolated mode."),
    ] = False,
) -> None:
    """Install the secret-redaction log filter and verify the launch posture.

    Fails closed: refuses to run unless Python is in ``-I`` isolated mode
    (``python -I -m wraith``), unless ``--allow-unisolated`` is passed. This
    stops a planted module in an artifact directory from shadowing a stdlib
    import (NFR-10).
    """
    logging.basicConfig(level=logging.INFO)
    install_secret_log_filter()
    if not sys.flags.isolated:
        message = (
            "WRAITH must be launched with 'python -I -m wraith' (isolated mode) "
            "so artifact directories cannot shadow stdlib imports (NFR-10)."
        )
        if allow_unisolated:
            typer.echo(
                f"WARNING: {message} Continuing because --allow-unisolated was set.",
                err=True,
            )
        else:
            typer.echo(
                f"ERROR: {message} Pass --allow-unisolated to override (development only).",
                err=True,
            )
            raise typer.Exit(code=2)


def _resolve_tool_versions() -> dict[str, str]:
    """Resolve runtime versions of WRAITH + the correctness-critical deps.

    Returns a ``{name: version}`` map recorded into the run manifest and ledger.
    A dependency that cannot be resolved (not installed under this interpreter)
    is recorded as ``"unknown"`` so the gap is surfaced, never silently omitted.
    """
    versions: dict[str, str] = {
        "wraith": WRAITH_VERSION,
        "python": sys.version.split()[0],
    }
    for dist in _CORRECTNESS_CRITICAL_DISTS:
        try:
            versions[dist] = importlib_metadata.version(dist)
        except importlib_metadata.PackageNotFoundError:
            versions[dist] = "unknown"
    return versions


@app.command()
def version() -> None:
    """Print the WRAITH version."""
    typer.echo(f"WRAITH {WRAITH_VERSION}")


@case_app.command("new")
def case_new(
    cases_root: CasesRoot,
    case_id: CaseId,
    operator: Annotated[str, typer.Option(help="Responsible operator.")],
    authorization_ref: Annotated[
        str | None, typer.Option(help="Engagement / authorization reference.")
    ] = None,
) -> None:
    """Create a new case workspace, ``case.json``, and canonical store."""
    workspace = create_workspace(cases_root, case_id)
    config = CaseConfig(
        case_id=case_id,
        operator=operator,
        authorization_ref=authorization_ref,
        created_at=datetime.now(UTC),
    )
    write_case_config(workspace.case_json, config)
    con = open_canonical_store(workspace.canonical_db)
    con.close()
    typer.echo(f"created case workspace: {workspace.root}")


@app.command()
def ingest(
    cases_root: CasesRoot,
    case_id: CaseId,
    inputs: Annotated[list[Path], typer.Option("--input", help="Artifact to ingest (repeatable).")],
    mode: Annotated[
        IngestMode, typer.Option(help="Copy into the case or reference by path.")
    ] = IngestMode.COPY,
    extract: Annotated[bool, typer.Option(help="Safely extract recognized archives.")] = False,
) -> None:
    """Ingest artifacts: hash + copy/reference, write manifest + ledger."""
    workspace = load_workspace(cases_root, case_id)
    config = load_case_config(workspace.case_json)
    run = IngestRun(
        case_id=config.case_id,
        operator=config.operator,
        tool_versions=_resolve_tool_versions(),
        parameters={"mode": mode.value, "extract": extract},
    )
    for source in inputs:
        ingest_file(workspace, run, source, mode=mode, extract=extract)

    # Write ordering: the immutable manifest is written FIRST, then the ledger
    # rows are committed. A crash between the two can only leave a manifest with
    # no ledger rows (re-ingest with a fresh id recovers it) — never ledger rows
    # orphaned without the authoritative manifest that documents the run.
    manifest = run.to_manifest(outputs=RunOutputs(canonical_db_path=str(workspace.canonical_db)))
    manifest_path = write_run_manifest(workspace.manifest_dir, manifest)
    con = open_canonical_store(workspace.canonical_db)
    try:
        write_ledger_rows(con, run.to_ledger_rows())
    finally:
        con.close()
    typer.echo(f"ingest_run_id: {run.ingest_run_id}")
    typer.echo(f"manifest: {manifest_path}")
    typer.echo(f"coverage: {run.coverage_counts}")
    typer.echo(f"skips: {run.skip_counts}")


@secret_app.command("init")
def secret_init(
    cases_root: CasesRoot,
    case_id: CaseId,
) -> None:
    """Create the per-case keyring (prompts for the operator passphrase)."""
    workspace = load_workspace(cases_root, case_id)
    if workspace.keyring_json.exists():
        typer.echo("ERROR: keyring already exists for this case.", err=True)
        raise typer.Exit(code=1)
    passphrase = _prompt_passphrase(confirm=True)
    keyring, _dek = create_keyring(case_id, passphrase)
    write_keyring(workspace.keyring_json, keyring)
    typer.echo(f"keyring created: {workspace.keyring_json}")


@secret_app.command("put")
def secret_put(
    cases_root: CasesRoot,
    case_id: CaseId,
    secret_type: Annotated[SecretType, typer.Option(help="Kind of secret.")],
    node_id: Annotated[str, typer.Option(help="Owning node id (or empty).")] = "",
    label: Annotated[str, typer.Option(help="Discriminator for multiple secrets.")] = "",
    ingest_run_id: Annotated[
        UUID | None,
        typer.Option(help="Producing ingest run id (defaults to a fresh id for a manual put)."),
    ] = None,
) -> None:
    """Store a secret value (prompted, never echoed) under the case DEK.

    The store is append-only and run-scoped: the returned ``secret_id`` folds in
    the producing ``ingest_run_id`` (a fresh id is minted for a manual put when
    none is given). Module 2's ``Principal.secret_refs`` carries this id.
    """
    workspace = load_workspace(cases_root, case_id)
    keyring = load_keyring(workspace.keyring_json)
    passphrase = _prompt_passphrase(confirm=False)
    dek = unwrap_dek(keyring, passphrase)
    value = getpass.getpass("Secret value (hidden): ").encode("utf-8")
    run_uuid = ingest_run_id or uuid4()
    store = SecretStore.open(workspace.secret_store_db, case_id)
    try:
        secret_id = store.put_secret(
            dek,
            ingest_run_id=run_uuid,
            secret_type=secret_type,
            node_id=node_id,
            plaintext=SecretBytes(value),
            label=label,
        )
    finally:
        store.close()
    typer.echo(f"ingest_run_id: {run_uuid}")
    typer.echo(f"stored secret_id: {secret_id}")


@secret_app.command("reveal")
def secret_reveal(
    cases_root: CasesRoot,
    case_id: CaseId,
    secret_id: Annotated[str, typer.Option(help="The secret_id to reveal.")],
    show: Annotated[
        bool, typer.Option(help="Print plaintext (hex). Off = redacted by default.")
    ] = False,
) -> None:
    """Reveal a stored secret (the only path to plaintext; redacted by default)."""
    workspace = load_workspace(cases_root, case_id)
    keyring = load_keyring(workspace.keyring_json)
    passphrase = _prompt_passphrase(confirm=False)
    dek = unwrap_dek(keyring, passphrase)
    store = SecretStore.open(workspace.secret_store_db, case_id)
    try:
        plaintext = store.reveal(secret_id, dek)
    except KeyError:
        typer.echo(f"ERROR: unknown secret_id {secret_id}", err=True)
        raise typer.Exit(code=1) from None
    except SecretDecryptError:
        typer.echo("ERROR: decryption failed (wrong passphrase or tampered record).", err=True)
        raise typer.Exit(code=1) from None
    finally:
        store.close()
    raw = plaintext.get_secret_value()
    if show:
        typer.echo(raw.hex())
    else:
        typer.echo(f"<redacted> ({len(raw)} bytes) — pass --show to print hex")


@export_app.command("bloodhound")
def export_bloodhound_cmd(
    cases_root: CasesRoot,
    case_id: CaseId,
    output_dir: Annotated[
        Path, typer.Option("--output-dir", help="Destination for the ingest files + zip.")
    ],
    ingest_version: Annotated[
        int,
        typer.Option(help="meta.version — MUST match the bundled BloodHound CE image."),
    ] = DEFAULT_INGEST_VERSION,
) -> None:
    """Export the (already-analyzed) canonical graph to BloodHound CE JSON.

    Reads the case's canonical store as-is (run ``analyze`` first to populate it)
    and writes per-type ingest files, a zip, and ``export_ledger.json`` (the
    provable no-silent-drop accounting) into ``output_dir``.
    """
    workspace = load_workspace(cases_root, case_id)
    config = ExportConfig(ingest_version=ingest_version)
    # Export is pure SELECTs: open the store READ-ONLY (no ledger DDL, no writes).
    con = open_canonical_store_readonly(workspace.canonical_db)
    try:
        result = export_bloodhound(con, output_dir, config)
    finally:
        con.close()
    typer.echo(f"nodes: {result.nodes_total}  edges: {result.edges_total}")
    typer.echo(f"exported: {result.edges_exported}  dropped: {result.edges_dropped}")
    if result.unmapped_kinds:
        typer.echo(f"WARNING: unmapped edge kinds (LOUD gap): {result.unmapped_kinds}", err=True)
    typer.echo(f"output: {result.output_dir}")


@app.command()
def serve(
    cases_root: CasesRoot,
    case_id: Annotated[
        str | None,
        typer.Option(
            help=(
                "Case id to bind as the single default store (read-only, legacy "
                "single-case mode). OMIT to run the full multi-case web UI "
                "(create/upload/analyze cases from the browser)."
            )
        ),
    ] = None,
    host: Annotated[str, typer.Option(help="Bind address (localhost by default).")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="TCP port for the local web UI backend.")] = 8713,
) -> None:
    """Serve the M7 web UI + analytics API (localhost; no network egress).

    Two modes:

    * **Multi-case web UI (default, ``--case-id`` omitted):** the full
      operate-everything app — create cases, upload artifacts, view live coverage,
      and run analyze from the browser. The writable ingest router is active; each
      analyzed case is served read-only through the per-case reader registry
      (``?case_id=`` on the read endpoints).
    * **Single-case read-only (``--case-id`` given):** binds that case's canonical
      store as the default reader (run ``analyze`` first to populate it).

    In both modes the built SPA (``ui/web/dist``) is auto-mounted at ``/`` when present.
    """
    import uvicorn

    from wraith.api.app import create_app

    if case_id is None:
        # Multi-case UI mode: no default store; cases are created/analyzed via the API.
        application = create_app(cases_root=cases_root)
    else:
        workspace = load_workspace(cases_root, case_id)
        if not Path(workspace.canonical_db).is_file():
            typer.echo("ERROR: canonical store not found; run 'wraith analyze' first.", err=True)
            raise typer.Exit(code=1)
        application = create_app(workspace.canonical_db, cases_root=cases_root)
    uvicorn.run(application, host=host, port=port, log_level="info")


@app.command()
def analyze(
    cases_root: CasesRoot,
    case_id: CaseId,
    ntds: Annotated[Path, typer.Option("--ntds", help="The NTDS .dit artifact.")],
    output_dir: Annotated[
        Path, typer.Option("--output-dir", help="Destination for the BloodHound export.")
    ],
    forest_id: Annotated[str, typer.Option(help="Scoping forest id.")] = "forest-default",
    system_hive: Annotated[
        Path | None, typer.Option("--system-hive", help="DC SYSTEM hive (ADCS-ESC ESC9/10).")
    ] = None,
    sam_hive: Annotated[
        Path | None, typer.Option("--sam-hive", help="A member-host SAM hive (AdminTo).")
    ] = None,
    sysvol: Annotated[
        Path | None, typer.Option("--sysvol", help="Acquired SYSVOL directory (GPO edges).")
    ] = None,
    ingest_version: Annotated[
        int, typer.Option(help="meta.version — MUST match the bundled BloodHound CE image.")
    ] = DEFAULT_INGEST_VERSION,
) -> None:
    """Run the full offline analysis chain, then export to BloodHound CE JSON.

    Wires the locked pass order (normalize -> membership -> edges -> ADCS-ESC ->
    host-SAM -> GPO/SYSVOL -> export) into one command so the exporter sees the
    complete graph. Each artifact is hashed + recorded; every pass's counted gaps
    flow into the run ledger + the export ledger.
    """
    workspace = load_workspace(cases_root, case_id)
    config = load_case_config(workspace.case_json)
    run = IngestRun(
        case_id=config.case_id,
        operator=config.operator,
        tool_versions=_resolve_tool_versions(),
        parameters={"forest_id": forest_id, "ingest_version": ingest_version},
    )
    sam_hosts = (SamHostInput(sam_path=sam_hive, system_hive_path=system_hive),) if sam_hive else ()
    inputs = PipelineInputs(
        ntds_path=ntds,
        forest_id=forest_id,
        system_hive_path=system_hive,
        sam_hosts=sam_hosts,
        sysvol_root=sysvol,
    )
    con = open_canonical_store(workspace.canonical_db)
    try:
        result = run_analysis_pipeline(
            con,
            run,
            inputs,
            output_dir=output_dir,
            export_config=ExportConfig(ingest_version=ingest_version),
        )
    finally:
        con.close()

    manifest = run.to_manifest(outputs=RunOutputs(canonical_db_path=str(workspace.canonical_db)))
    write_run_manifest(workspace.manifest_dir, manifest)
    led = open_canonical_store(workspace.canonical_db)
    try:
        write_ledger_rows(led, run.to_ledger_rows())
    finally:
        led.close()
    typer.echo(f"domain: {result.domain_fqdn} ({result.domain_id})")
    typer.echo(f"edges exported: {result.export_result.edges_exported}")
    typer.echo(f"edges dropped:  {result.export_result.edges_dropped}")
    if result.export_result.unmapped_kinds:
        typer.echo(
            f"WARNING: unmapped edge kinds (LOUD gap): {result.export_result.unmapped_kinds}",
            err=True,
        )
    typer.echo(f"skips: {result.skip_counts}")
    typer.echo(f"output: {result.export_result.output_dir}")


def _prompt_passphrase(*, confirm: bool) -> bytes:
    """Read the operator passphrase via getpass (never echoed, never stored).

    Inputs:
        confirm: if True, prompt twice and require a match.

    Returns:
        The passphrase as UTF-8 bytes (the caller derives the KEK then drops it).

    Failure modes:
        Exits with code 1 if confirmation does not match.
    """
    first = getpass.getpass("Operator passphrase: ")
    if confirm:
        second = getpass.getpass("Confirm passphrase: ")
        if first != second:
            typer.echo("ERROR: passphrases did not match.", err=True)
            raise typer.Exit(code=1)
    return first.encode("utf-8")


if __name__ == "__main__":
    app()
