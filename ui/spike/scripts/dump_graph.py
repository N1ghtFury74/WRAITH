"""THROWAWAY spike helper: dump the canonical DuckDB graph to graph.json.

Reads the §3 node tables (principal/container/gpo/adcs) and the §4 edge table
from a WRAITH canonical store and emits the graphology-shaped JSON the sigma
spike loads:

    {nodes:[{id,label,kind}], edges:[{source,target,kind}]}

Edges whose endpoints are NOT both modeled nodes are dropped and counted (the
graph-internal subset). Run with `python -I` against the venv.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import duckdb


def main(db_path: str, out_path: str) -> None:
    con = duckdb.connect(db_path, read_only=True)
    try:
        nodes: list[dict[str, str]] = []
        node_ids: set[str] = set()

        def add(node_id: str, label: str | None, kind: str | None) -> None:
            if node_id in node_ids:
                return
            node_ids.add(node_id)
            nodes.append(
                {
                    "id": node_id,
                    "label": (label or node_id),
                    "kind": (kind or "Unknown"),
                }
            )

        # §3.1 principal -> label = samaccountname, kind = principal_type
        for nid, label, kind in con.execute(
            "SELECT node_id, samaccountname, principal_type FROM principal"
        ).fetchall():
            add(nid, label, kind)

        # §3.2 container/OU/domain -> label = DN leaf, kind = container_type
        for nid, dn, kind in con.execute(
            "SELECT node_id, distinguished_name, container_type FROM container"
        ).fetchall():
            leaf = dn.split(",")[0].split("=")[-1] if dn else None
            add(nid, leaf, kind)

        # §3.3 gpo -> label = display_name, kind = GPO
        for nid, label in con.execute(
            "SELECT node_id, display_name FROM gpo"
        ).fetchall():
            add(nid, label, "GPO")

        # §3.5 adcs -> label = name, kind = adcs_type
        for nid, label, kind in con.execute(
            "SELECT node_id, name, adcs_type FROM adcs"
        ).fetchall():
            add(nid, label, kind)

        # §4 edge -> keep only edges where BOTH endpoints are modeled nodes.
        raw_edges = con.execute(
            "SELECT source_node_id, target_node_id, kind FROM edge"
        ).fetchall()

        edges: list[dict[str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        dropped_endpoint = 0
        dropped_dup = 0
        for src, dst, kind in raw_edges:
            if src not in node_ids or dst not in node_ids:
                dropped_endpoint += 1
                continue
            key = (src, dst, kind)
            if key in seen:
                dropped_dup += 1
                continue
            seen.add(key)
            edges.append({"source": src, "target": dst, "kind": kind})
    finally:
        con.close()

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"nodes": nodes, "edges": edges}), encoding="utf-8")

    print(f"nodes dumped:        {len(nodes)}")
    print(f"edges total (store): {len(raw_edges)}")
    print(f"edges kept (graph):  {len(edges)}")
    print(f"edges dropped (endpoint not a node): {dropped_endpoint}")
    print(f"edges dropped (duplicate kind/pair): {dropped_dup}")
    print(f"wrote {out}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
