"""Case Manager: workspace layout, ``case.json``, run manifest, ``IngestRun``.

This package owns the case workspace lifecycle and the single-source-of-truth
``IngestRun`` context from which provenance structs and ledger rows are minted.
"""

from __future__ import annotations

from wraith.case.case import CaseConfig, load_case_config, write_case_config
from wraith.case.ingest_run import IngestRun
from wraith.case.manifest import (
    ArtifactInput,
    HostEnvironment,
    RunManifest,
    RunOutputs,
    Timings,
    load_run_manifest,
    write_run_manifest,
)
from wraith.case.workspace import CaseWorkspace, create_workspace, load_workspace

__all__ = [
    "CaseConfig",
    "write_case_config",
    "load_case_config",
    "CaseWorkspace",
    "create_workspace",
    "load_workspace",
    "IngestRun",
    "ArtifactInput",
    "HostEnvironment",
    "RunManifest",
    "RunOutputs",
    "Timings",
    "write_run_manifest",
    "load_run_manifest",
]
