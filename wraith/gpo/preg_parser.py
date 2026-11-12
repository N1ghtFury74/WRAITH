"""WRAITH-native, bounds-checked ``Registry.pol`` (preg) reader ([MS-GPREG]).

The format is tiny and fully specified, so we reuse the FORMAT (public
[MS-GPREG] 2.2.1) and write original, defensive code — never a foreign parser.
Treating SYSVOL as untrusted input, every field length is validated against the
remaining buffer before slicing, so a malformed/truncated record or an absurd
declared ``size`` degrades to a counted gap, never an out-of-bounds read or a
crash. Valid records decoded before a bad one are retained.

Structure:

* 8-byte header: signature DWORD ``0x67655250`` (ASCII ``PReg``) + version DWORD.
* body: a sequence of ``[key;value;type;size;data]`` records where the brackets
  and ``;`` separators are UTF-16LE characters, ``key``/``value`` are
  null-terminated UTF-16LE strings, ``type``/``size`` are little-endian DWORDs,
  and ``data`` is exactly ``size`` raw bytes (may be binary — Margosis's
  corrections: binary interleaved with UTF-16LE text, root hive implied by the
  Machine/User parent dir).
"""

from __future__ import annotations

import logging

from wraith.gpo.models import PregRecord, PregResult

_log = logging.getLogger(__name__)

#: ASCII ``PReg`` little-endian signature DWORD (bytes ``50 52 65 67``).
_MAGIC: bytes = b"PReg"

#: UTF-16LE encodings of the record framing characters.
_OPEN: bytes = b"[\x00"
_CLOSE: bytes = b"]\x00"
_SEP: bytes = b";\x00"
_NUL: bytes = b"\x00\x00"

#: ``REG_DWORD`` little-endian type tag (for :func:`dword_value`).
REG_DWORD: int = 4
REG_SZ: int = 1
REG_BINARY: int = 3


def _read_utf16z(raw: bytes, pos: int) -> tuple[str | None, int]:
    """Read a null-terminated UTF-16LE string starting at ``pos``.

    Scans two bytes at a time for the ``00 00`` terminator (so a lone ``00`` in
    a surrogate/codepoint is not mistaken for the end). Returns ``(text, next)``
    where ``next`` is the offset just past the terminator, or ``(None, pos)`` if
    no terminator is found within the buffer (a malformed record).
    """
    end = pos
    n = len(raw)
    while end + 1 < n:
        if raw[end : end + 2] == _NUL:
            text = raw[pos:end].decode("utf-16-le", "replace")
            return text, end + 2
        end += 2
    return None, pos


def parse_registry_pol(raw: bytes) -> PregResult:
    """Parse a ``Registry.pol`` blob into its records (crash-free, bounds-checked).

    Inputs:
        raw: the raw ``Registry.pol`` bytes.

    Returns:
        A :class:`PregResult`. ``ok=False`` with a ``reason`` on a bad magic,
        truncation, or any bounds violation; records decoded before the failure
        are retained in ``records`` so partial content is not lost.

    Failure modes:
        Never raises — all input errors become ``ok=False`` + a counted gap.
    """
    n = len(raw)
    if n < 8 or raw[:4] != _MAGIC:
        return PregResult(records=(), ok=False, reason="bad_magic")
    version = int.from_bytes(raw[4:8], "little")

    records: list[PregRecord] = []
    pos = 8
    while pos < n:
        if raw[pos : pos + 2] != _OPEN:
            return _fail(records, version, "missing_open_bracket")
        pos += 2

        key, pos = _read_utf16z(raw, pos)
        if key is None:
            return _fail(records, version, "unterminated_key")
        if raw[pos : pos + 2] != _SEP:
            return _fail(records, version, "missing_sep_after_key")
        pos += 2

        value, pos = _read_utf16z(raw, pos)
        if value is None:
            return _fail(records, version, "unterminated_value")
        if raw[pos : pos + 2] != _SEP:
            return _fail(records, version, "missing_sep_after_value")
        pos += 2

        if pos + 4 > n:
            return _fail(records, version, "truncated_type")
        reg_type = int.from_bytes(raw[pos : pos + 4], "little")
        pos += 4
        if raw[pos : pos + 2] != _SEP:
            return _fail(records, version, "missing_sep_after_type")
        pos += 2

        if pos + 4 > n:
            return _fail(records, version, "truncated_size")
        size = int.from_bytes(raw[pos : pos + 4], "little")
        pos += 4
        if raw[pos : pos + 2] != _SEP:
            return _fail(records, version, "missing_sep_after_size")
        pos += 2

        # The load-bearing bounds check: never trust the declared size.
        if size > n - pos:
            return _fail(records, version, "data_size_overflow")
        data = raw[pos : pos + size]
        pos += size

        if raw[pos : pos + 2] != _CLOSE:
            return _fail(records, version, "missing_close_bracket")
        pos += 2

        records.append(PregRecord(key=key, value=value, reg_type=reg_type, size=size, data=data))

    return PregResult(records=tuple(records), ok=True, reason=None, version=version)


def _fail(records: list[PregRecord], version: int, reason: str) -> PregResult:
    """Build a failed :class:`PregResult`, retaining records parsed so far."""
    _log.debug("gpo: Registry.pol parse stopped: %s", reason)
    return PregResult(records=tuple(records), ok=False, reason=reason, version=version)


def dword_value(record: PregRecord) -> int | None:
    """Return the ``REG_DWORD`` integer value of ``record``, or ``None``.

    Returns ``None`` when the record is not a 4-byte DWORD (so binary/str
    records never mis-decode to a spurious integer).

    Failure modes:
        Never raises.
    """
    if record.reg_type == REG_DWORD and len(record.data) >= 4:
        return int.from_bytes(record.data[:4], "little")
    return None
