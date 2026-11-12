"""Enable ``python -I -m wraith`` (the mandated isolated-mode entrypoint)."""

from __future__ import annotations

from wraith.cli import app

if __name__ == "__main__":
    app()
