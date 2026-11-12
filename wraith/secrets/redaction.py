"""Logging backstop that scrubs secret-looking values (NFR-05).

Type-level redaction (pydantic ``SecretStr``/``SecretBytes``) is the PRIMARY and
authoritative defense: a value typed as a secret is replaced with
``<redacted>`` wherever it appears in a record (``msg``, positional/keyword
``args``, and any ``extra=`` structured field). This filter is a backstop that
also catches a raw NT/LM hash that slipped through as a plain string.

Why attach to *handlers*, not the logger object: a ``logging.Filter`` on a
logger only runs for records logged *directly* on that logger. Records from
child loggers (``wraith.secrets.*``, ``wraith.cli``) propagate to the root
logger's *handlers* and bypass any filter attached to the root logger itself.
Attaching the filter to every handler guarantees it runs for every record that
reaches a sink, whatever logger produced it (see ``install_secret_log_filter``).

Hex backstop scope: the raw-hex heuristic is deliberately narrow — EXACTLY 32
hex characters (the NT/LM hash shape) — and is applied ONLY to records emitted
by the ``wraith.secrets`` logger subtree. This avoids colliding with non-secret
forensic identifiers: ``image_sha256``/``node_id``/``edge_id``/``secret_id`` are
64-hex and never match a 32-char token, and 32-hex forensic values elsewhere
(e.g. dashless GUIDs) are out of scope because they are not logged under the
secrets logger. Type-redaction (above) is the real guarantee; this is defence
in depth for the one place a bare hash could leak.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping

from pydantic import SecretBytes, SecretStr

#: The shape of ``logging.LogRecord.args`` (positional tuple or mapping).
_ArgsType = tuple[object, ...] | Mapping[str, object]

#: Placeholder written in place of a redacted value.
REDACTED: str = "<redacted>"

#: Logger subtree whose records get the raw-hex backstop applied.
_SECRET_LOGGER_PREFIX: str = "wraith.secrets"  # noqa: S105 (logger-name prefix, not a secret)

#: NT/LM hashes are EXACTLY 32 hex chars. A ``\b...\b`` boundary means a longer
#: run (e.g. a 64-hex SHA-256) never matches, so forensic ids are never touched.
_NTLM_HEX = re.compile(r"\b[0-9a-fA-F]{32}\b")

#: Standard ``LogRecord`` attribute names — anything outside this set is an
#: operator-supplied ``extra=`` field and is eligible for structured scrubbing.
_STANDARD_ATTRS: frozenset[str] = frozenset(vars(logging.makeLogRecord({}))) | {
    "message",
    "asctime",
}


class SecretRedactionFilter(logging.Filter):
    """A ``logging.Filter`` that redacts secret-looking content on every record.

    Behavior:
        * Any ``SecretStr``/``SecretBytes`` in ``record.msg``, ``record.args``,
          or an ``extra=`` field is replaced with ``<redacted>``.
        * For records from the ``wraith.secrets`` subtree only, NT/LM-shaped
          32-hex tokens in the rendered string(s) are masked as a backstop.

    The filter always returns ``True`` (records are kept, only sanitized).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Sanitize ``record`` in place; always keep the record.

        Inputs:
            record: the log record about to be emitted.

        Returns:
            ``True`` always (the record is kept, with secrets scrubbed).

        Failure modes:
            None — redaction is best-effort and never raises.
        """
        apply_hex = record.name.startswith(_SECRET_LOGGER_PREFIX)
        record.args = self._scrub_args(record.args, apply_hex=apply_hex)
        if isinstance(record.msg, (SecretStr, SecretBytes)):
            record.msg = REDACTED
        elif isinstance(record.msg, str) and apply_hex:
            record.msg = _NTLM_HEX.sub(REDACTED, record.msg)
        self._scrub_extras(record, apply_hex=apply_hex)
        return True

    @staticmethod
    def _scrub_args(args: _ArgsType | None, *, apply_hex: bool) -> _ArgsType | None:
        """Replace any secret-typed values inside the log args."""
        if args is None:
            return None
        if isinstance(args, tuple):
            return tuple(SecretRedactionFilter._scrub_value(a, apply_hex=apply_hex) for a in args)
        return {
            k: SecretRedactionFilter._scrub_value(v, apply_hex=apply_hex) for k, v in args.items()
        }

    @staticmethod
    def _scrub_extras(record: logging.LogRecord, *, apply_hex: bool) -> None:
        """Scrub operator-supplied ``extra=`` fields (the store logs via these).

        Type-redaction applies to every extra; the NT/LM hex backstop applies
        only when the record is from the secrets subtree. Standard ``LogRecord``
        attributes are never touched.
        """
        for key, value in list(record.__dict__.items()):
            if key in _STANDARD_ATTRS:
                continue
            record.__dict__[key] = SecretRedactionFilter._scrub_value(value, apply_hex=apply_hex)

    @staticmethod
    def _scrub_value(value: object, *, apply_hex: bool) -> object:
        """Redact a single value if it is (or renders as) a secret."""
        if isinstance(value, (SecretStr, SecretBytes)):
            return REDACTED
        if apply_hex and isinstance(value, str):
            return _NTLM_HEX.sub(REDACTED, value)
        return value


def install_secret_log_filter(logger: logging.Logger | None = None) -> SecretRedactionFilter:
    """Attach the redaction filter to every handler of a logger (root default).

    The filter is installed on the logger's *handlers* (not the logger object)
    so it also runs for records that propagate up from child loggers. Call this
    AFTER handlers are configured (e.g. after ``logging.basicConfig``); if the
    logger has no handlers yet this is a no-op and should be called again once a
    handler exists.

    Inputs:
        logger: the logger whose handlers to protect; the root logger if
            ``None``.

    Returns:
        The installed ``SecretRedactionFilter`` (reused across handlers; never
        added twice to the same handler).

    Failure modes:
        None.
    """
    target = logger if logger is not None else logging.getLogger()
    flt = SecretRedactionFilter()
    for handler in target.handlers:
        existing = next((f for f in handler.filters if isinstance(f, SecretRedactionFilter)), None)
        if existing is not None:
            flt = existing
            continue
        handler.addFilter(flt)
    return flt
