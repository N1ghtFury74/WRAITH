"""WRAITH M7 read-only data/analytics API (FastAPI over the canonical DuckDB).

Public entry point: :func:`wraith.api.app.create_app`. The package is read-only
over the store and performs no network egress in the request path.
"""

from __future__ import annotations

from wraith.api.app import API_PREFIX, DB_ENV_VAR, create_app

__all__ = ["API_PREFIX", "DB_ENV_VAR", "create_app"]
