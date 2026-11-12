"""WebSocket progress channel source (M7).

Reuses the run ledger's coverage/skip counts (the WRAITH "never silent" gaps)
as the progress feed. In M7 there is no live API-driven ingest, so the channel
REPLAYS the latest run's per-artifact ledger rows deterministically: a snapshot,
one progress event per source file (with its coverage/skip counters), then a
terminal ``done`` event. A later live-ingest producer pushes the same event
shapes onto the same channel with no client change (additive).
"""

from __future__ import annotations

from wraith.api.store import StoreReader


def progress_events(reader: StoreReader) -> list[dict[str, object]]:
    """Build the ordered progress event list from the latest run's ledger.

    Inputs:
        reader: the read-only store accessor.

    Returns:
        A deterministic list of JSON-able event dicts:
        ``{"type":"snapshot", "artifacts":N}`` then one
        ``{"type":"progress", ...}`` per source file (in ``source_file`` order)
        then ``{"type":"done", ...}``. An empty ledger yields a single ``done``
        with ``artifacts=0``.

    Failure modes:
        Never raises; a store without a ledger yields the empty-run terminal.
    """
    rows = reader.latest_run_counts()
    events: list[dict[str, object]] = [{"type": "snapshot", "artifacts": len(rows)}]
    total = len(rows)
    for i, row in enumerate(rows, start=1):
        events.append(
            {
                "type": "progress",
                "step": i,
                "steps": total,
                "source_file": row.get("source_file"),
                "coverage_counts": row.get("coverage_counts"),
                "skip_counts": row.get("skip_counts"),
            }
        )
    events.append({"type": "done", "artifacts": total})
    return events
