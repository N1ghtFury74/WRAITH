"""Tier-B GPO / SYSVOL-derived edges and facts (offline, dead-disk).

This package turns an acquired SYSVOL tree into the §4 edges and §3.3 GPO
``derived_rights`` facts that BloodHound's ``GPOLocalGroup`` collection and the
Synacktiv user-rights enrichment would produce — computed natively for the
offline case, never by contacting a host.

It REUSES Module 5's already-emitted structural edges (``Contains`` and
``GPLink``) to resolve a GPO's affected computers; it does NOT recompute
containment or re-parse ``gPLink`` (disabled links were already dropped and
counted in M3). Everything it emits is ``confidence="inferred"`` because full
RSoP (WMI filters, security filtering, block-inheritance, link precedence)
cannot be evaluated offline — WRAITH mirrors SharpHound's union-of-non-disabled
links and records the precedence/filtering blind spot as a documented caveat.

Parsers (all pure, all crash-free — malformed input degrades to a counted gap):

* :mod:`wraith.gpo.inf_parser` — ``GptTmpl.inf`` via stdlib ``configparser``
  (UTF-16LE-BOM decode + case-preserving option keys).
* :mod:`wraith.gpo.preg_parser` — a WRAITH-native, bounds-checked ``Registry.pol``
  ([MS-GPREG] preg) reader.
* :mod:`wraith.gpo.gpp_parser` — GPP ``Groups.xml`` via stdlib ElementTree, plus
  the public [MS-GPPREF] static-key ``cpassword`` decryption.

Library licenses: configparser / ElementTree / uuid / struct = PSF (stdlib);
the preg parser is WRAITH-native (public [MS-GPREG] format); AES for cpassword
reuses the already-pinned ``cryptography`` dependency. No new third-party deps.
"""

from __future__ import annotations

from wraith.gpo.engine import process_sysvol
from wraith.gpo.gpp_parser import decrypt_gpp_cpassword, parse_gpp_document, parse_groups_xml
from wraith.gpo.inf_parser import decode_inf_bytes, parse_gpttmpl
from wraith.gpo.models import (
    GpoProcessResult,
    GppCpassword,
    GppDocument,
    GppGroup,
    GppMember,
    GppPasswordFinding,
    GptTmplData,
    GroupMembership,
    PregRecord,
    PregResult,
    PrivilegeRight,
    RegistrySignal,
)
from wraith.gpo.preg_parser import parse_registry_pol

__all__ = [
    "GpoProcessResult",
    "GppCpassword",
    "GppDocument",
    "GppGroup",
    "GppMember",
    "GppPasswordFinding",
    "GptTmplData",
    "GroupMembership",
    "PregRecord",
    "PregResult",
    "PrivilegeRight",
    "RegistrySignal",
    "decode_inf_bytes",
    "decrypt_gpp_cpassword",
    "parse_gpp_document",
    "parse_groups_xml",
    "parse_gpttmpl",
    "parse_registry_pol",
    "process_sysvol",
]
