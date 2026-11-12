"""WRAITH M7 FastAPI application — read-only analytics + writable case/ingest.

Resource-oriented, versioned under ``/api/v1``. Two routers are mounted:

* the **read-only** query layer (summary, graph slice + neighbors, pathfinding,
  dossier, risk, search, the WS progress channel, the reserved ``/behavior``
  stub) — it never writes the store; and
* the **writable** case/ingest + coverage router (:mod:`wraith.api.ingest`) that
  lets an operator run the whole workflow from the UI.

Readers are managed by a per-case :class:`~wraith.api.registry.CaseReaderRegistry`
on ``app.state`` (doc 14 §8a decision 1): the query layer stays strictly
read-only, and a case's reader is bound only AFTER its background analyze closes
the write handle (DuckDB single-writer). ``create_app(db_path)`` still opens one
*default* reader for backward compatibility with the CLI ``serve`` command and the
existing M7 gate. Offline by construction: no outbound network call anywhere in
the request path. Secrets are returned only as redacted references.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal, cast

from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)

from wraith import WRAITH_VERSION
from wraith.acquisition.paths import PathSafetyError
from wraith.api.behavior import router as behavior_router
from wraith.api.connector import build_connectors
from wraith.api.dossier import build_dossier
from wraith.api.graph import DEFAULT_LIMIT, build_slice
from wraith.api.ingest import CaseRunManager, build_ingest_router
from wraith.api.merge import build_merge_overlay, read_divergence_ledger
from wraith.api.models import (
    CaseSummary,
    ConnectorRequest,
    ConnectorResult,
    DivergenceLedgerOut,
    GlossaryOut,
    GraphSlice,
    NodeDossier,
    NodeListEntry,
    NodeListPage,
    NodeRef,
    NodeRisk,
    PathRequest,
    PathResult,
    PrebuiltQuery,
    PrebuiltQueryResult,
    PrebuiltQueryRunRequest,
    RiskSummary,
    SearchResult,
    SliceRequest,
    SourceCoverage,
    SourceList,
)
from wraith.api.paths import build_case_path_graph, find_paths, find_paths_to
from wraith.api.progress import progress_events
from wraith.api.queries import (
    UnknownQueryError,
    UnsupportedQueryError,
    list_queries,
    run_query,
)
from wraith.api.registry import CaseReaderRegistry
from wraith.api.rights_glossary import build_glossary
from wraith.api.risk import score_nodes, summarize_risk
from wraith.api.sources import list_sources, resolve_scoped_reader, source_coverage
from wraith.api.store import ScopedStoreReader, StoreReader
from wraith.case.workspace import load_workspace

API_PREFIX = "/api/v1"

#: Environment variable naming the canonical store when no path is passed.
DB_ENV_VAR = "WRAITH_CANONICAL_DB"

#: Environment variable naming the writable cases root (server config; never
#: client-supplied). Defaults to ``./cases`` (doc 14 §3).
CASES_ROOT_ENV_VAR = "WRAITH_CASES_ROOT"

#: Degenerate ``GET /graph/default`` fallback: when a case has no Tier-0 node, seed
#: the canvas with this many top-risk nodes instead (counted as a gap, never silent).
DEFAULT_RISK_SEED_N = 25

#: Environment variable overriding the built SPA ``dist`` directory to serve.
#: Defaults to ``<repo>/ui/web/dist`` (FE-1). The mount is additive + optional:
#: if the directory (with an ``index.html``) is absent, nothing is mounted and
#: the app stays API-only (headless runs + the M7 gate are unaffected).
UI_DIST_ENV_VAR = "WRAITH_UI_DIST"


def _resolve_db_path(db_path: Path | str | None) -> Path | None:
    """Resolve the optional default-reader store path (arg or env var, else None)."""
    raw = db_path if db_path is not None else os.environ.get(DB_ENV_VAR)
    return Path(raw) if raw else None


def _resolve_cases_root(cases_root: Path | str | None) -> Path:
    """Resolve the writable cases root (arg or ``WRAITH_CASES_ROOT`` or ``./cases``)."""
    raw = cases_root if cases_root is not None else os.environ.get(CASES_ROOT_ENV_VAR)
    return Path(raw) if raw else Path("cases")


def create_app(db_path: Path | str | None = None, cases_root: Path | str | None = None) -> FastAPI:
    """Build the FastAPI app (read-only query + writable case/ingest).

    Inputs:
        db_path: optional path to a populated ``canonical.duckdb`` opened as the
            lifetime *default* reader (the CLI ``serve`` / M7 gate path). ``None``
            (or the ``WRAITH_CANONICAL_DB`` env var) leaves no default reader;
            case-scoped endpoints still work via the registry.
        cases_root: writable cases root for the ingest router (arg /
            ``WRAITH_CASES_ROOT`` env / ``./cases``).

    Returns:
        A configured :class:`fastapi.FastAPI` instance.

    Failure modes:
        Raises ``FileNotFoundError`` at startup if ``db_path`` is given but the
        store file is missing.
    """
    resolved_db = _resolve_db_path(db_path)
    resolved_cases_root = _resolve_cases_root(cases_root)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        default_reader = StoreReader.open(resolved_db) if resolved_db is not None else None
        registry = CaseReaderRegistry(default_reader)
        manager = CaseRunManager(registry, resolved_cases_root)
        app.state.registry = registry
        app.state.cases_root = resolved_cases_root
        app.state.run_manager = manager
        try:
            yield
        finally:
            manager.shutdown()
            registry.close_all()

    app = FastAPI(
        title="WRAITH API",
        version=WRAITH_VERSION,
        summary="Offline Active Directory relationship mapper — analytics + case ingest API.",
        lifespan=lifespan,
    )
    app.include_router(_build_router())
    _mount_spa_if_present(app)
    return app


def _resolve_ui_dist() -> Path:
    """Resolve the built SPA ``dist`` directory (env override or repo default)."""
    raw = os.environ.get(UI_DIST_ENV_VAR)
    if raw:
        return Path(raw)
    # app.py lives at ``<repo>/wraith/api/app.py`` -> repo root is parents[2].
    return Path(__file__).resolve().parents[2] / "ui" / "web" / "dist"


def _mount_spa_if_present(app: FastAPI) -> None:
    """Mount the built React SPA at ``/`` with a history-API fallback (additive).

    Offline integrated mode: ``wraith serve`` serves the vendored SPA bundle so an
    operator runs the whole workflow from one origin, with the API staying under
    ``/api/v1``. The mount is strictly optional — it is skipped unless the ``dist``
    directory and its ``index.html`` both exist — so API-only / headless runs and
    the existing M7 gate (which never builds the UI) are unaffected.

    Behaviour:
        * ``dist/assets`` is served as hashed static files;
        * any other GET that is not an ``/api`` path and does not resolve to a real
          file under ``dist`` returns ``index.html`` so client-side deep links
          (``/case/<id>/graph``) load the SPA, which then routes;
        * ``/api`` paths never fall through to the SPA (a genuine API 404 stays a
          typed JSON 404, never an HTML page).
    """
    dist = _resolve_ui_dist()
    index = dist / "index.html"
    if not index.is_file():
        return

    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    #: ``index.html`` (and small root files like favicon) MUST revalidate every
    #: load. The bundle under ``/assets`` is content-hashed, so a new build is a
    #: new URL — but the browser only learns the new URLs by re-reading
    #: ``index.html``. Without ``no-cache`` the browser serves a stale cached
    #: ``index.html`` that still references the OLD hashes, so rebuilds never
    #: appear ("nothing changes" after a deploy). ``no-cache`` = always
    #: revalidate (cheap 304 when unchanged); the hashed assets stay long-lived.
    _spa_headers = {"Cache-Control": "no-cache"}

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str) -> FileResponse:
        """Serve a real dist file if present, else the SPA ``index.html``.

        All responses carry ``Cache-Control: no-cache`` so the browser always
        revalidates and picks up a new build's content-hashed asset URLs
        immediately (the content-addressed ``/assets`` files never go stale).
        """
        if full_path.startswith("api"):
            raise HTTPException(status_code=404, detail="not found")
        if full_path:
            try:
                candidate = (dist / full_path).resolve()
                candidate.relative_to(dist.resolve())
            except (OSError, ValueError):
                candidate = index
            if candidate.is_file():
                return FileResponse(candidate, headers=_spa_headers)
        return FileResponse(index, headers=_spa_headers)


def _registry(request: Request) -> CaseReaderRegistry:
    """Return the app's reader registry (lifespan-provided)."""
    registry = getattr(request.app.state, "registry", None)
    if registry is None:  # pragma: no cover - lifespan always sets it
        raise HTTPException(status_code=503, detail="store not initialized")
    return cast("CaseReaderRegistry", registry)


_log = logging.getLogger(__name__)


def get_reader(
    request: Request,
    case_id: Annotated[str | None, Query()] = None,
) -> StoreReader:
    """FastAPI dependency resolving the read-only store reader for a request.

    This is the single resolver shared by every read-only query endpoint, so the
    ``case_id`` selection rule lives in exactly one place.

    Inputs:
        request: the incoming request (carries the app's reader registry).
        case_id: optional query parameter naming a case whose analyzed store
            should be served; omitted selects the lifetime *default* reader.

    Returns:
        The read-only :class:`StoreReader` to serve this request from.

    Failure modes (all typed, never a silent ``None`` reader):
        * ``case_id`` given and bound -> that case's reader.
        * ``case_id`` given, case exists but no reader bound yet (not analyzed /
          analyze still running) -> 409 ``{reason: "case_not_ready"}``.
        * ``case_id`` given but no such case on disk -> 404 ``{reason:
          "unknown_case"}`` (400 ``{reason: "unsafe_case_id"}`` if it is unsafe).
        * ``case_id`` omitted and a default reader is bound -> the default reader
          (preserves the CLI ``serve --case-id`` single-case mode + the M7 gate).
        * ``case_id`` omitted and no default reader -> 400 ``{reason:
          "case_id_required"}``.
    """
    registry = _registry(request)
    if case_id is not None:
        reader = registry.get(case_id)
        if reader is not None:
            return reader
        # Not bound in memory (e.g. after a server restart, which clears the
        # registry): lazy-bind the case's read-only store if it has been analyzed,
        # so an analyzed case survives a restart without a re-analyze. An existing
        # but un-analyzed case stays 409; unknown/unsafe stay 404/400; a corrupt
        # store is a typed 409, never a silent 500.
        cases_root = getattr(request.app.state, "cases_root", None)
        if cases_root is None:  # pragma: no cover - lifespan always sets it
            raise HTTPException(status_code=404, detail={"reason": "unknown_case"})
        try:
            workspace = load_workspace(cases_root, case_id)
        except PathSafetyError as exc:
            raise HTTPException(status_code=400, detail={"reason": "unsafe_case_id"}) from exc
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail={"reason": "unknown_case"}) from None
        if not Path(workspace.canonical_db).is_file():
            raise HTTPException(status_code=409, detail={"reason": "case_not_ready"})
        try:
            return registry.get_or_bind(case_id, workspace.canonical_db)
        except Exception as exc:  # noqa: BLE001 - corrupt/locked store -> typed, not 500
            _log.warning("lazy-bind failed for case %s", case_id)
            raise HTTPException(
                status_code=409, detail={"reason": "case_store_unreadable"}
            ) from exc
    reader = registry.default
    if reader is None:
        raise HTTPException(status_code=400, detail={"reason": "case_id_required"})
    return reader


#: Annotated dependency alias (avoids a call in the default — ruff B008) so the
#: FastAPI handlers read ``reader: ReaderDep`` instead of ``= Depends(...)``.
ReaderDep = Annotated[StoreReader, Depends(get_reader)]


def get_scoped_reader(
    reader: ReaderDep,
    source_id: Annotated[str | None, Query()] = None,
) -> StoreReader:
    """Resolve an optional per-source VIEW over the case reader (multi-source, M-MS2).

    The single shared dependency for every read endpoint that supports the
    ``?source_id=`` per-source filter. When ``source_id`` is omitted the base
    (case) reader is returned UNCHANGED — the unscoped path is byte-identical +
    zero-overhead. When given, a source-scoped reader is returned (an unknown/empty
    ``source_id`` is NOT an error — it is a filter that yields an honestly empty view
    with a counted ``source.unknown_or_empty`` gap, surfaced in each response's
    ``counted_gaps``).
    """
    return resolve_scoped_reader(reader, source_id)


#: Dependency alias for endpoints that honor the optional ``?source_id=`` filter.
ScopedReaderDep = Annotated[StoreReader, Depends(get_scoped_reader)]


def _compute_scored(reader: StoreReader) -> list[NodeRisk]:
    """Score every principal + the Domain object once (shared by /risk endpoints)."""
    principals = reader.principal_risk_inputs() + reader.domain_risk_inputs()
    return score_nodes(principals, reader.all_edges(), reader.tier0_sets())


def _build_router() -> APIRouter:
    router = APIRouter(prefix=API_PREFIX)

    @router.get("", tags=["meta"])
    def api_root() -> dict[str, str]:
        """API banner: version + offline posture."""
        return {"name": "WRAITH API", "version": WRAITH_VERSION, "offline": "true"}

    @router.get("/glossary", response_model=GlossaryOut, tags=["meta"])
    def glossary() -> GlossaryOut:
        """The static rights/attributes glossary (doc 21 §4) for guided-dossier annotation.

        Read-only and NOT case-scoped — a pure, offline, static reference the
        frontend fetches once to annotate every ACE / flag by kind. No reader, no
        store access, no secret.
        """
        return build_glossary()

    @router.get("/summary", response_model=CaseSummary, tags=["case"])
    def summary(reader: ScopedReaderDep) -> CaseSummary:
        """Landing-dashboard counts + the domain/case context.

        Supports the optional ``?source_id=`` per-source filter (M-MS2): with it the
        counts are for that source's observed objects only; without it (the single-
        source path) the output is byte-identical to before.
        """
        domain_id, domain_fqdn, fl = reader.domain_identity()
        return CaseSummary(
            domain_id=domain_id,
            domain_fqdn=domain_fqdn,
            functional_level=fl,
            node_count=reader.node_count(),
            edge_count=reader.edge_count(),
            node_kind_counts=reader.node_kind_counts(),
            edge_kind_counts=reader.edge_kind_counts(),
            tier0_node_count=len(reader.tier0_sets().classified_ids),
            dcsync_holder_count=len(
                {e.source_node_id for e in reader.all_edges() if e.kind == "DCSync"}
            ),
            counted_gaps=dict(reader.scope_gaps),
        )

    @router.get("/sources", response_model=SourceList, tags=["sources"])
    def sources(reader: ReaderDep) -> SourceList:
        """List the DC artifact sets (sources) in the case + per-source counts (M-MS2).

        How an operator/UI DISCOVERS the sources to then read standalone via the
        ``?source_id=`` filter on the other read endpoints. Whole-case view (NOT
        itself source-scoped). Empty on a pre-multi-source store.
        """
        return list_sources(reader)

    @router.get("/sources/{source_id}/coverage", response_model=SourceCoverage, tags=["sources"])
    def source_coverage_endpoint(source_id: str, reader: ReaderDep) -> SourceCoverage:
        """Per-source coverage/skip counts (contract §5 item 3, M-MS2).

        Aggregated from the provenance ledger by the source's artifact SHA-256s. An
        unknown source or a SHA with no ledger row is a COUNTED gap, never a silent
        empty.
        """
        return source_coverage(reader, source_id)

    # NOTE: the former reader-based GET /cases (synthetic single "current" entry)
    # was removed — the authoritative case list is the disk-enumerating
    # GET /cases in the ingest router, which works in multi-case mode (no bound
    # reader) and lets the UI offer a case picker instead of asking for an id.

    @router.post("/graph/slice", response_model=GraphSlice, tags=["graph"])
    def graph_slice(body: SliceRequest, reader: ScopedReaderDep) -> GraphSlice:
        """Return a bounded, deterministic server-side graph slice for the canvas.

        A NARROWED slice (``tier0_only`` or ``node_kinds``) is a filtered RESULT view,
        not an unfiltered drill-in, so it stays canonical-only — it must never pull the
        whole ``Base`` leaf population back into a view the user explicitly narrowed
        (owner decision 2026-10-29; mirrors ``/graph/default``). ``build_slice`` also
        enforces this on its own; this pass makes the endpoint's intent explicit.

        Supports the optional ``?source_id=`` per-source filter (M-MS2): the slice is
        built over ONLY that source's observed nodes/edges; unscoped is unchanged.
        """
        narrowed = body.tier0_only or bool(body.node_kinds)
        sl = build_slice(
            reader,
            seed_node_ids=body.seed_node_ids,
            search=body.search,
            node_kinds=body.node_kinds,
            edge_kinds=body.edge_kinds,
            tier0_only=body.tier0_only,
            depth=body.depth,
            limit=body.limit,
            layout=body.layout,
            expand_base_endpoints=not narrowed,
        )
        sl.counted_gaps = {**sl.counted_gaps, **reader.scope_gaps}
        return sl

    @router.post("/graph/connector", response_model=ConnectorResult, tags=["graph"])
    def graph_connector(body: ConnectorRequest, reader: ReaderDep) -> ConnectorResult:
        """Connect-the-dots: minimal labelled connecting chains for a retained node set.

        For a canvas slice whose retained nodes share no direct edge (the
        ``noEdges`` state — e.g. a User+GPO filter), compute the minimal connecting
        chains through hidden intermediate objects over the ONE H2-filtered attack
        graph, returned in TWO never-conflated lanes (doc 09): ``control`` chains
        (real ``principal -> object`` capability, ranked first) and ``scope`` chains
        (``GPO -> container -> principal`` application, potential offline — each
        carrying the RSoP caveat and counting ``rsop_not_resolvable``). Structural
        co-location is suppressed (counted), chain confidence is the weakest hop, and
        an empty result carries an explicit ``note`` — never a silent blank. All work
        is bounded by ``max_hops`` / ``max_paths`` / ``max_pairs`` and deterministic.
        """
        return build_connectors(
            reader,
            body.node_ids,
            max_hops=body.max_hops,
            max_paths=body.max_paths,
            max_pairs=body.max_pairs,
        )

    @router.get("/nodes", response_model=NodeListPage, tags=["nodes"])
    def nodes_list(
        reader: ScopedReaderDep,
        kind: Annotated[str | None, Query()] = None,
        q: Annotated[str | None, Query()] = None,
        sort: Annotated[Literal["name", "kind", "risk", "tier"], Query()] = "name",
        order: Annotated[Literal["asc", "desc"], Query()] = "asc",
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> NodeListPage:
        """Bounded, case-scoped browse-by-type node list (Dossiers + Risk UI).

        Reads one page over the node union (optionally ``kind``-filtered and/or
        ``q``-substring-filtered). ``tier``/``highvalue`` come from the Tier-0
        classification set (same source as ``/graph/slice``); ``risk_score`` comes
        from the shared scored map (``_compute_scored`` — the same one source of
        truth the ``/risk/*`` endpoints use) and is ``None`` for non-principal kinds
        the risk model does not score. ``sort=name|kind`` is ordered in SQL;
        ``sort=risk|tier`` is ordered over the scored map. Always bounded
        (``limit <= 200``); bad params -> a typed 422. No secret fields.
        """
        # One source of truth: the same scored map the /risk/* endpoints build.
        # Computed once per request (bounded; may be memoized per-reader later —
        # doc 18 open-risk #1). name|kind ordering stays pure SQL; the map is used
        # to order risk|tier and to decorate the risk_score column consistently.
        tier0_ids = reader.tier0_sets().classified_ids
        risk_by_id = {nr.node_id: nr.score for nr in _compute_scored(reader)}
        page = reader.nodes_page(
            kind=kind,
            q=q,
            sort=sort,
            order=order,
            limit=limit,
            offset=offset,
            risk_by_id=risk_by_id,
            tier0_ids=tier0_ids,
        )
        entries = [
            NodeListEntry(
                node_id=r.node_id,
                kind=r.kind,
                label=r.label,
                object_sid=r.object_sid,
                tier=0 if r.node_id in tier0_ids else None,
                risk_score=risk_by_id.get(r.node_id),
                highvalue=r.node_id in tier0_ids,
            )
            for r in page.rows
        ]
        return NodeListPage(
            entries=entries,
            total_matched=page.total_matched,
            returned=len(entries),
            offset=offset,
            limit=limit,
            truncated=page.truncated,
            counted_gaps=dict(reader.scope_gaps),
        )

    @router.get("/nodes/{node_id}", response_model=NodeDossier, tags=["nodes"])
    def node_dossier(
        node_id: str,
        reader: ScopedReaderDep,
        case_id: Annotated[str | None, Query()] = None,
    ) -> NodeDossier:
        """Full per-entity dossier: identity, flags, edges, memberships, secrets, risk.

        Supports the optional ``?source_id=`` per-source filter (M-MS2): a node NOT
        observed by that source is a 404 (the per-source dossier shows only that
        source's objects); its edges/memberships are scoped to the source.

        Multi-source merge overlay (M-MS5a): when a ``case_id`` is given, this is the
        UNSCOPED (folded) view, AND an opt-in merge has run for the case, the dossier
        carries a ``merge`` block with each divergent attribute's presented value +
        three-state badge (``no_divergence`` / ``resolved`` / ``contested_unresolved``).
        On the single-source / non-merged / per-source (``?source_id=``) path NO overlay
        is attached and the dossier serialization is BYTE-UNCHANGED (the ``merge`` key is
        omitted entirely) — zero regression.
        """
        dossier = build_dossier(reader, node_id)
        if dossier is None:
            raise HTTPException(status_code=404, detail=f"unknown node_id: {node_id}")
        dossier.counted_gaps = {**dossier.counted_gaps, **reader.scope_gaps}
        # Overlay ONLY on the folded (unscoped) case view; a per-source scoped reader is
        # the per-source-separate landing, which is never merge-folded (contract §5.4).
        if case_id is not None and not isinstance(reader, ScopedStoreReader):
            dossier.merge = build_merge_overlay(reader, node_id, case_id)
        return dossier

    @router.get("/divergence", response_model=DivergenceLedgerOut, tags=["merge"])
    def divergence_ledger(
        reader: ReaderDep,
        case_id: Annotated[str | None, Query()] = None,
    ) -> DivergenceLedgerOut:
        """The divergence ledger for a case's current merge run (contract §3.4, M-MS5a).

        Returns the ledger rows (``obj_kind``/``obj_id``/``attribute``/
        ``divergence_type``/``resolution``/``resolved_by``/``value_by_source`` +
        ``resolved_value``) plus the DC-vs-DC report counts. Secrets stay redacted — a
        ``secret_divergence`` row's ``value_by_source`` is the ``{present, differs}`` map
        only, never a digest/plaintext. A case with no merge run yet returns an honest
        empty ledger (``merged=false`` + a counted ``merge.no_merge_run`` gap). ``case_id``
        is required (divergence is a case/merge concept).
        """
        if case_id is None:
            raise HTTPException(status_code=400, detail={"reason": "case_id_required"})
        return read_divergence_ledger(reader, case_id)

    @router.get("/nodes/{node_id}/neighbors", response_model=GraphSlice, tags=["graph"])
    def node_neighbors(
        node_id: str,
        reader: ScopedReaderDep,
        depth: Annotated[int, Query(ge=0, le=6)] = 1,
        limit: Annotated[int, Query(ge=1, le=5000)] = DEFAULT_LIMIT,
        edge_kinds: Annotated[list[str] | None, Query()] = None,
        layout: Annotated[str, Query()] = "auto",
    ) -> GraphSlice:
        """Lazy expand-on-click: the neighbourhood around one node as a slice.

        Supports the optional ``?source_id=`` per-source filter (M-MS2).
        """
        sl = build_slice(
            reader,
            seed_node_ids=[node_id],
            edge_kinds=edge_kinds,
            depth=depth,
            limit=limit,
            layout=layout,
        )
        sl.counted_gaps = {**sl.counted_gaps, **reader.scope_gaps}
        return sl

    @router.get("/graph/default", response_model=GraphSlice, tags=["graph"])
    def graph_default(reader: ScopedReaderDep) -> GraphSlice:
        """The default canvas: the Tier-0 depth-1 neighborhood (design §7.1 / §13).

        Returns ``build_slice(seed=tier0_sets().classified_ids, depth=1, all edge
        kinds, limit=DEFAULT_LIMIT)`` — the densest, most decision-relevant first
        screen (never a lonely node-kind filter). If the case has no Tier-0
        (degenerate), it falls back to seeding the top-``N`` risk nodes and records
        a counted gap in the response (never a silent empty/misleading canvas).
        """
        # Supports the optional ``?source_id=`` per-source filter (M-MS2): the default
        # canvas is built over ONLY that source's Tier-0 neighbourhood.
        tier0_ids = sorted(reader.tier0_sets().classified_ids)
        if tier0_ids:
            # expand_base_endpoints=False: the default canvas stays canonical — a
            # Tier-0-dense seed set must not pull in the whole Base leaf population
            # (owner decision 2026-10-29: the default graph slice excludes Base).
            sl = build_slice(
                reader,
                seed_node_ids=tier0_ids,
                depth=1,
                limit=DEFAULT_LIMIT,
                expand_base_endpoints=False,
            )
            sl.counted_gaps = {**sl.counted_gaps, **reader.scope_gaps}
            return sl
        top_ids = [nr.node_id for nr in _compute_scored(reader)[:DEFAULT_RISK_SEED_N]]
        if not top_ids:
            # Degenerate-of-degenerate: no Tier-0 AND no scored nodes. An empty seed
            # would make build_slice expand to the WHOLE graph, so short-circuit to an
            # honest empty slice with its own counted gap (never a whole-graph dump).
            return GraphSlice(
                nodes=[],
                edges=[],
                total_matched=0,
                returned=0,
                truncated=False,
                layout="none",
                seed_node_ids=[],
                depth=1,
                counted_gaps={"no_tier0_no_risk_nodes": 1, **reader.scope_gaps},
            )
        sl = build_slice(
            reader,
            seed_node_ids=top_ids,
            depth=1,
            limit=DEFAULT_LIMIT,
            expand_base_endpoints=False,
        )
        # Merge (not overwrite) so a slice-level counted gap (e.g. an unresolved edge
        # endpoint from Base materialization) is preserved alongside this fallback flag.
        sl.counted_gaps = {**sl.counted_gaps, "no_tier0_fallback_top_risk": 1, **reader.scope_gaps}
        return sl

    @router.get("/analysis/queries", response_model=list[PrebuiltQuery], tags=["analysis"])
    def analysis_queries(reader: ReaderDep) -> list[PrebuiltQuery]:
        """The frozen prebuilt attack-query catalog with live source-set counts (§3.1)."""
        return list_queries(reader)

    @router.post(
        "/analysis/queries/{query_id}/run",
        response_model=PrebuiltQueryResult,
        tags=["analysis"],
    )
    def analysis_query_run(
        query_id: str,
        reader: ReaderDep,
        body: PrebuiltQueryRunRequest | None = None,
    ) -> PrebuiltQueryResult:
        """Run one catalog query (bounded). Unknown id -> 404; unsupported -> 422."""
        req = body or PrebuiltQueryRunRequest()
        try:
            return run_query(reader, query_id, max_hops=req.max_hops, max_paths=req.max_paths)
        except UnknownQueryError as exc:
            raise HTTPException(
                status_code=404, detail={"reason": "unknown_query", "query_id": query_id}
            ) from exc
        except UnsupportedQueryError as exc:
            raise HTTPException(
                status_code=422,
                detail={"reason": "query_not_supported", "query_id": query_id, "why": exc.reason},
            ) from exc

    @router.post("/paths", response_model=PathResult, tags=["paths"])
    def paths(body: PathRequest, reader: ReaderDep) -> PathResult:
        """Attacker pathfinding (networkx) from/to a principal and Tier-0 (or a target).

        ``direction="outbound"`` (default) is the existing behavior, byte-identical:
        ``find_paths`` from ``source_node_ids`` to the target. ``direction="inbound"``
        routes to the single bounded ``find_paths_to`` reverse BFS — the request's
        ``target``/``target_node_ids`` is the SINK and ``source_node_ids`` (+ a
        resolvable ``source_sid``) is the optional source filter; omit both for the
        global "who can reach this sink" query.
        """
        sources = list(body.source_node_ids or [])
        if body.source_sid:
            resolved = reader.node_id_by_sid(body.source_sid)
            if resolved:
                sources.append(resolved)
        # ONE H2-filtered per-case graph (full Tier-0 classification group set) so
        # H2 holds uniformly regardless of target (design §14 [HIGH]).
        pg = build_case_path_graph(reader)
        if body.direction == "inbound":
            return find_paths_to(
                reader,
                target=body.target,
                target_node_ids=body.target_node_ids,
                source_filter=sources if sources else None,
                max_hops=body.max_hops,
                max_paths=body.max_paths,
                path_graph=pg,
            )
        if not sources:
            raise HTTPException(
                status_code=422, detail="source_node_ids or a resolvable source_sid is required"
            )
        return find_paths(
            reader,
            source_node_ids=sources,
            target=body.target,
            target_node_ids=body.target_node_ids,
            max_hops=body.max_hops,
            max_paths=body.max_paths,
            all_simple=body.all_simple,
            path_graph=pg,
        )

    @router.get("/risk/nodes", response_model=list[NodeRisk], tags=["risk"])
    def risk_nodes(
        reader: ScopedReaderDep,
        limit: Annotated[int, Query(ge=1, le=5000)] = 100,
        min_score: Annotated[int, Query(ge=0)] = 0,
    ) -> list[NodeRisk]:
        """Transparent per-node risk scores (ranked), each with its itemized factors.

        Supports the optional ``?source_id=`` per-source filter (M-MS2): scores are
        computed over ONLY that source's principals/edges. (A bare list cannot carry a
        ``counted_gaps`` field; an unknown/empty source is surfaced on ``/summary`` and
        ``/risk/summary``.)
        """
        scored = [nr for nr in _compute_scored(reader) if nr.score >= min_score]
        return scored[:limit]

    @router.get("/risk/nodes/{node_id}", response_model=NodeRisk, tags=["risk"])
    def risk_node(node_id: str, reader: ScopedReaderDep) -> NodeRisk:
        """The transparent risk score + factors for a single principal.

        Supports the optional ``?source_id=`` per-source filter (M-MS2): a principal
        not observed by that source is a 404.
        """
        for nr in _compute_scored(reader):
            if nr.node_id == node_id:
                return nr
        raise HTTPException(status_code=404, detail=f"no scored principal: {node_id}")

    @router.get("/risk/summary", response_model=RiskSummary, tags=["risk"])
    def risk_summary(
        reader: ScopedReaderDep,
        top: Annotated[int, Query(ge=0, le=200)] = 10,
    ) -> RiskSummary:
        """Aggregate risk stats + the top-scored nodes for the dashboard.

        Supports the optional ``?source_id=`` per-source filter (M-MS2).
        """
        summ = summarize_risk(_compute_scored(reader), top)
        summ.counted_gaps = dict(reader.scope_gaps)
        return summ

    @router.get("/search", response_model=SearchResult, tags=["search"])
    def search(
        reader: ReaderDep,
        q: Annotated[str, Query(min_length=1)],
        limit: Annotated[int, Query(ge=1, le=500)] = 25,
    ) -> SearchResult:
        """Search by name / SID / sAMAccountName / UPN / DN (typeahead-friendly)."""
        hits = reader.search(q, limit + 1)
        truncated = len(hits) > limit
        hits = hits[:limit]
        return SearchResult(
            query=q,
            hits=[NodeRef(node_id=h.node_id, kind=h.kind, label=h.label) for h in hits],
            count=len(hits),
            truncated=truncated,
        )

    @router.websocket("/ws/progress")
    async def ws_progress(
        websocket: WebSocket,
        case_id: Annotated[str | None, Query()] = None,
    ) -> None:
        """Stream analyze progress (additive, doc 14 §3.6).

        With a ``case_id`` that has an active/recent run, streams live
        ``snapshot``/``progress``/``done`` events (with ``pass``/``pct``/``state``)
        from the worker-thread run state. Otherwise replays the latest run's
        coverage/skip ledger from the matching reader — the exact pre-existing
        behavior for a connection with no ``case_id`` (a client needs no change).
        """
        await websocket.accept()
        manager = cast("CaseRunManager | None", getattr(websocket.app.state, "run_manager", None))
        try:
            if case_id and manager is not None and manager.latest_run(case_id) is not None:
                async for event in manager.stream(case_id):
                    await websocket.send_json(event)
            else:
                reader = _ws_reader(websocket, case_id)
                if reader is not None:
                    for event in progress_events(reader):
                        await websocket.send_json(event)
                else:
                    await websocket.send_json({"type": "snapshot", "artifacts": 0})
                    await websocket.send_json({"type": "done", "artifacts": 0})
            await websocket.close()
        except WebSocketDisconnect:  # pragma: no cover - client hangup
            return

    router.include_router(behavior_router)
    router.include_router(build_ingest_router())
    return router


def _ws_reader(websocket: WebSocket, case_id: str | None) -> StoreReader | None:
    """Pick the reader for a ledger-replay WS: the case reader if bound, else default."""
    registry = cast("CaseReaderRegistry | None", getattr(websocket.app.state, "registry", None))
    if registry is None:  # pragma: no cover - lifespan always sets it
        return None
    if case_id:
        case_reader = registry.get(case_id)
        if case_reader is not None:
            return case_reader
    return registry.default
