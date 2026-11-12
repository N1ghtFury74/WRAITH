"""Case workspace layout: create/load the ``cases/<case_id>/`` tree.

The workspace is the self-contained evidence package. All paths are derived
from the validated, contained case root so nothing can be written outside it
(NFR-10). ``artifacts/`` is treated read-only by every downstream module.
"""

from __future__ import annotations

from pathlib import Path

from wraith.acquisition.paths import resolve_within, validate_case_id
from wraith.model.store import CANONICAL_DB_FILENAME
from wraith.secrets.store import STORE_DB_FILENAME

#: Subdirectories created inside every case workspace.
_SUBDIRS: tuple[str, ...] = (
    "manifest",
    "artifacts",
    "secrets",
    "exports",
    "dossiers",
    "logs",
    "provenance",
)


class CaseWorkspace:
    """Resolved, contained view of a single case's on-disk layout.

    Construct via :func:`create_workspace` or :func:`load_workspace`; the root
    is already validated and resolved.
    """

    def __init__(self, root: Path) -> None:
        """Wrap an already-resolved case root. Prefer the module functions."""
        self._root = root

    @property
    def root(self) -> Path:
        """The resolved case root directory ``cases/<case_id>/``."""
        return self._root

    @property
    def case_json(self) -> Path:
        """Path to ``case.json`` (case-level metadata)."""
        return self._root / "case.json"

    @property
    def manifest_dir(self) -> Path:
        """Path to the ``manifest/`` directory (one file per ingest run)."""
        return self._root / "manifest"

    @property
    def latest_manifest(self) -> Path:
        """Path to ``manifest/latest.json`` (pointer to the newest run)."""
        return self.manifest_dir / "latest.json"

    @property
    def artifacts_dir(self) -> Path:
        """Path to ``artifacts/`` (acquired inputs; read-only downstream)."""
        return self._root / "artifacts"

    @property
    def canonical_db(self) -> Path:
        """Path to the canonical DuckDB store."""
        return self._root / CANONICAL_DB_FILENAME

    @property
    def secrets_dir(self) -> Path:
        """Path to the ``secrets/`` directory."""
        return self._root / "secrets"

    @property
    def keyring_json(self) -> Path:
        """Path to ``secrets/keyring.json`` (wrapped DEK + KDF metadata)."""
        return self.secrets_dir / "keyring.json"

    @property
    def secret_store_db(self) -> Path:
        """Path to ``secrets/store.duckdb`` (ciphertext-only secret records)."""
        return self.secrets_dir / STORE_DB_FILENAME

    @property
    def exports_dir(self) -> Path:
        """Path to ``exports/``."""
        return self._root / "exports"

    @property
    def dossiers_dir(self) -> Path:
        """Path to ``dossiers/``."""
        return self._root / "dossiers"

    @property
    def logs_dir(self) -> Path:
        """Path to ``logs/``."""
        return self._root / "logs"

    @property
    def provenance_dir(self) -> Path:
        """Path to ``provenance/`` (human-readable chain-of-custody exports)."""
        return self._root / "provenance"


def _case_root(cases_root: Path | str, case_id: str) -> Path:
    """Validate ``case_id`` and resolve its contained root under ``cases_root``."""
    validate_case_id(case_id)
    cases_root_path = Path(cases_root).resolve()
    cases_root_path.mkdir(parents=True, exist_ok=True)
    return resolve_within(cases_root_path, case_id)


def create_workspace(cases_root: Path | str, case_id: str) -> CaseWorkspace:
    """Create the full workspace directory tree for a new case.

    Inputs:
        cases_root: the parent directory holding all cases.
        case_id: validated case id (see ``validate_case_id``).

    Returns:
        A ``CaseWorkspace`` with all subdirectories created.

    Failure modes:
        Raises ``wraith.acquisition.paths.PathSafetyError`` if ``case_id`` is
        unsafe; ``FileExistsError`` if the case already exists; ``OSError`` on
        a filesystem error.
    """
    root = _case_root(cases_root, case_id)
    if root.exists():
        raise FileExistsError(f"case already exists: {root}")
    root.mkdir(parents=True)
    for sub in _SUBDIRS:
        (root / sub).mkdir()
    return CaseWorkspace(root)


def load_workspace(cases_root: Path | str, case_id: str) -> CaseWorkspace:
    """Load an existing case workspace.

    Inputs:
        cases_root: the parent directory holding all cases.
        case_id: validated case id.

    Returns:
        A ``CaseWorkspace`` pointing at the existing case root.

    Failure modes:
        Raises ``PathSafetyError`` if ``case_id`` is unsafe;
        ``FileNotFoundError`` if the case does not exist.
    """
    root = _case_root(cases_root, case_id)
    if not root.is_dir():
        raise FileNotFoundError(f"case does not exist: {root}")
    return CaseWorkspace(root)
