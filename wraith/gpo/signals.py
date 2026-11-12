"""Map parsed registry policy values to attack-relevant :class:`RegistrySignal`.

Surfaces the research 10 §5 catalog from ``Registry.pol`` records and from
``GptTmpl.inf`` ``[Registry Values]`` lines. These are node facts / findings,
not graph edges (posture signals, not traversable capability) — the
conservative BloodHound stance for v1.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from wraith.gpo.constants import REGISTRY_SIGNAL_CATALOG
from wraith.gpo.models import PregRecord, RegistrySignal
from wraith.gpo.preg_parser import REG_DWORD, dword_value


def _render_value(reg_type: int, data: bytes, dword: int | None) -> str:
    """Render a registry value as stable text (DWORD decimal; binary as a size)."""
    if dword is not None:
        return str(dword)
    if reg_type == REG_DWORD:
        return "<malformed dword>"
    if not data:
        return ""
    return f"<{len(data)} bytes>"


def signals_from_preg(
    records: Iterable[PregRecord],
    source_file: str,
    image_sha256: str,
    directory_timestamp: datetime | None = None,
) -> list[RegistrySignal]:
    """Surface catalog signals from parsed ``Registry.pol`` records.

    Inputs:
        records: the decoded :class:`PregRecord` list.
        source_file: the SYSVOL-relative path of the ``Registry.pol`` file.
        image_sha256: SHA-256 of the SYSVOL artifact (stamped on each signal).
        directory_timestamp: the source file's image mtime (UTC), if known.

    Returns:
        One :class:`RegistrySignal` per record whose value NAME is in the catalog
        (binary blobs like the EFS cert are correctly NOT mis-read as signals).

    Failure modes:
        Never raises.
    """
    signals: list[RegistrySignal] = []
    for record in records:
        entry = REGISTRY_SIGNAL_CATALOG.get(record.value.lower())
        if entry is None:
            continue
        label, interpretation = entry
        dword = dword_value(record)
        signals.append(
            RegistrySignal(
                signal=label,
                key=record.key,
                value_name=record.value,
                raw_value=_render_value(record.reg_type, record.data, dword),
                interpretation=interpretation,
                source_file=source_file,
                image_sha256=image_sha256,
                directory_timestamp=directory_timestamp,
            )
        )
    return signals


def signals_from_registry_values(
    registry_values: Iterable[tuple[str, str]],
    source_file: str,
    image_sha256: str,
    directory_timestamp: datetime | None = None,
) -> list[RegistrySignal]:
    """Surface catalog signals from GptTmpl ``[Registry Values]`` lines.

    A secedit ``[Registry Values]`` line is ``<MACHINE\\...\\ValueName>=<type>,<value>``;
    the value name is the last path component. The raw ``type,value`` string is
    kept verbatim as ``raw_value``.

    Inputs:
        registry_values: the ``(full_key, raw_value)`` lines.
        source_file: the SYSVOL-relative path of the ``GptTmpl.inf`` file.
        image_sha256: SHA-256 of the SYSVOL artifact (stamped on each signal).
        directory_timestamp: the source file's image mtime (UTC), if known.

    Failure modes:
        Never raises.
    """
    signals: list[RegistrySignal] = []
    for full_key, raw_value in registry_values:
        value_name = full_key.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]
        entry = REGISTRY_SIGNAL_CATALOG.get(value_name.lower())
        if entry is None:
            continue
        label, interpretation = entry
        signals.append(
            RegistrySignal(
                signal=label,
                key=full_key,
                value_name=value_name,
                raw_value=raw_value,
                interpretation=interpretation,
                source_file=source_file,
                image_sha256=image_sha256,
                directory_timestamp=directory_timestamp,
            )
        )
    return signals
