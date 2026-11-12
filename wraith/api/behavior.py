"""Reserved ``/api/v1/behavior`` endpoint family (NOT implemented in M7).

Documented and shaped now so behavioral baselining (M3) is purely additive: the
future per-entity behavior summary / timeline reads a SEPARATE time-partitioned
event store (Parquet/DuckDB) joined on ``node_id`` (the ``behavior_summary_ref``
hook the frozen schema reserves), with NO change to the graph endpoints. Every
route here returns HTTP 501 with an explanatory body until baselining is built.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/behavior", tags=["behavior (reserved)"])

_RESERVED = {
    "status": "not_implemented",
    "reason": "behavioral baselining (M3) is reserved; this endpoint family is a documented "
    "stub so it can be added without reshaping the graph API or the frozen schema.",
}


@router.get("/nodes/{node_id}", status_code=501)
def behavior_for_node(node_id: str) -> JSONResponse:
    """Reserved: per-entity behavior summary/timeline (auth/process events). 501 in M7."""
    return JSONResponse(status_code=501, content={**_RESERVED, "node_id": node_id})


@router.get("", status_code=501)
def behavior_root() -> JSONResponse:
    """Reserved behavior family root. Returns 501 with the reservation note."""
    return JSONResponse(status_code=501, content=_RESERVED)
