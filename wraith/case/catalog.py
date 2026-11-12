"""Frozen artifact -> capability catalog (doc 14 §1; derived from doc 08 §2-§3).

Pure constants + pydantic shapes, no I/O. This is the single source of truth the
coverage function (:mod:`wraith.case.coverage`), the upload-kind validator, and
the UI's required/optional checklist all read. Nothing here opens a file, touches
the network, or depends on wall-clock — it is a declarative table.

The catalog answers one question honestly: *given the artifact SET an operator
uploaded, which capabilities (edge classes) can WRAITH produce, and for every one
it cannot, which counted ``gap_class`` explains the loss* — so an "unavailable"
is NEVER silent (CLAUDE.md: counted gap on every degraded/absent branch).

Reserved kinds (now only ``additional_dc``) have ``pipeline_field=None``: uploading
one stores + registers it (provenance) but the pass that would consume it is not
wired yet, so its capability stays unavailable and the API must not imply the pass
runs (doc 14 §1.2 rationale, §7 risk). ``ca_host_registry`` was reserved until
module 35b wired it to ``PipelineInputs.ca_host_system_path`` (+ the optional
SOFTWARE companion / ``ca_host_fqdn``); it is now a fully wired optional kind.
"""

from __future__ import annotations

from typing import Final, Literal

from pydantic import BaseModel, ConfigDict

Necessity = Literal["required", "optional"]
Effect = Literal["degraded", "unavailable"]


class CapabilityEffect(BaseModel):
    """What losing ONE artifact does to ONE capability (doc 14 §1.1).

    Fields:
        capability_id: FK to :class:`Capability.id`.
        effect: ``"degraded"`` (partial) or ``"unavailable"`` (none).
        gap_class: the counted-gap key bumped via ``IngestRun.bump_skip`` and
            reported by the coverage function as the UI reason (never silent).
        note: one-line human reason.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    capability_id: str
    effect: Effect
    gap_class: str
    note: str


class ArtifactKind(BaseModel):
    """One acquirable artifact kind (doc 14 §1.1).

    Fields:
        id: stable slug; equals the upload ``kind`` form field.
        label: human label for the UI tile.
        necessity: ``"required"`` (only ``ntds_dit``) or ``"optional"``.
        pipeline_field: the :class:`~wraith.export.pipeline.PipelineInputs` field
            this feeds, or ``None`` when reserved (no pass consumes it yet).
        multi: ``True`` => repeatable (member SAMs, additional DCs).
        canonical_source_file: the provenance ``source_file`` pattern (the
            ``:<host>`` suffix is substituted for ``multi`` kinds).
        unlocks: capability ids this artifact is the primary source for.
        absence_effects: per-capability loss when THIS artifact is absent.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    label: str
    necessity: Necessity
    pipeline_field: str | None
    multi: bool = False
    canonical_source_file: str
    unlocks: tuple[str, ...]
    absence_effects: tuple[CapabilityEffect, ...]


class Capability(BaseModel):
    """One producible capability / edge class (doc 14 §1.1; tier from doc 08 §3).

    Fields:
        id: stable capability id.
        label: human description.
        tier: doc-08 tier. NOTE: declared ``str`` (not ``Literal["A".."D"]``)
            because doc 08 / doc 14 §1.2 assign ``"A/D"`` (base facts feed Tier-D
            composites) and ``"—"`` (multi-forest, untiered) which a single-letter
            Literal cannot hold. Carrying the doc-08 string verbatim keeps the
            catalog the faithful source of truth (flagged to the orchestrator).
        requires_all: artifact ids that must ALL be present for ``available``.
        degrades_without: artifact ids whose absence => ``degraded`` (partial),
            not ``unavailable``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    label: str
    tier: str
    requires_all: tuple[str, ...]
    degrades_without: tuple[str, ...]


# --- capability ids (referenced by both tables; kept as names to avoid typos) --
_CORE = "core_directory_graph"
_ADCS_BASE = "adcs_base_facts"
_SECRETS = "secret_recovery"
_ESC_DC = "adcs_esc_dc_config"
_GPO = "gpo_driven_edges"
_HOST_ADMINTO = "host_adminto"
_CA_HOST = "ca_host_edges"
_MULTI_DOM = "multi_domain_forest"

#: Coverage reason emitted when the hard-required ``ntds_dit`` is absent. Not a
#: doc 14 §1.2 counted gap (ntds absent is a hard 422, not a coverage gap), but
#: surfaced as a reason so a capability is never shown "unavailable" silently.
NO_NTDS_GAP_CLASS: Final[str] = "core_unavailable_no_ntds_dit"


CATALOG: Final[tuple[ArtifactKind, ...]] = (
    ArtifactKind(
        id="ntds_dit",
        label="NTDS database (ntds.dit)",
        necessity="required",
        pipeline_field="ntds_path",
        multi=False,
        canonical_source_file="ntds.dit",
        unlocks=(_CORE, _ADCS_BASE),
        absence_effects=(),  # hard error (422), not a coverage gap (doc 14 §1.2)
    ),
    ArtifactKind(
        id="system_hive",
        label="DC SYSTEM registry hive",
        necessity="optional",
        pipeline_field="system_hive_path",
        multi=False,
        canonical_source_file="SYSTEM",
        unlocks=(_SECRETS, _ESC_DC),
        absence_effects=(
            CapabilityEffect(
                capability_id=_SECRETS,
                effect="unavailable",
                gap_class="secrets_unavailable_no_system_hive",
                note="PEK/secret decryption needs the DC SYSTEM hive boot key.",
            ),
            CapabilityEffect(
                capability_id=_ESC_DC,
                effect="unavailable",
                gap_class="esc_dc_config_undecidable_no_system_hive",
                note="ESC9/ESC10 undecidable without the DC cert-mapping registry.",
            ),
            CapabilityEffect(
                capability_id=_ADCS_BASE,
                effect="degraded",
                gap_class="adcs_dc_config_degraded_no_system_hive",
                note="Template/CA facts still emit; DC-side cert-mapping unknown.",
            ),
        ),
    ),
    ArtifactKind(
        id="sysvol",
        label="SYSVOL tree (GPO files)",
        necessity="optional",
        pipeline_field="sysvol_root",
        multi=False,
        canonical_source_file="SYSVOL",
        unlocks=(_GPO,),
        absence_effects=(
            CapabilityEffect(
                capability_id=_GPO,
                effect="unavailable",
                gap_class="gpo_edges_unavailable_no_sysvol",
                note="GPO-driven edges live only in the SYSVOL policy files.",
            ),
        ),
    ),
    ArtifactKind(
        id="member_sam",
        label="Member-host SAM (+opt SYSTEM)",
        necessity="optional",
        pipeline_field="sam_hosts",
        multi=True,
        canonical_source_file="SAM:<host>",
        unlocks=(_HOST_ADMINTO,),
        absence_effects=(
            CapabilityEffect(
                capability_id=_HOST_ADMINTO,
                effect="unavailable",
                gap_class="host_adminto_unavailable_no_member_sam",
                note="Non-GPO local admin lives only in each host SAM (doc 08 §4.4).",
            ),
        ),
    ),
    ArtifactKind(
        id="ca_host_registry",
        label="Enterprise-CA host SYSTEM/SOFTWARE",
        necessity="optional",
        # Wired (module 35b): the composite upload carries the CA host's SYSTEM hive
        # (the primary ``file``, mapped to ``PipelineInputs.ca_host_system_path`` —
        # the field named here, so the ``pipeline_field is None <=> reserved``
        # invariant now reports this kind WIRED) plus an OPTIONAL SOFTWARE companion
        # hive (``software_file`` -> ``ca_host_software_path``, the DCOM plane) and an
        # optional ``ca_host_fqdn``, exactly as ``member_sam`` carries a SAM + a
        # companion SYSTEM under one kind / one pipeline_field. The SOFTWARE-absent
        # case is already a counted ENGINE gap (``dcom_restrictions_absent``), so it
        # needs no separate catalog kind here; the absence of the whole CA hive is
        # the ``absence_effects`` below (ManageCA/full-ESC unavailable).
        pipeline_field="ca_host_system_path",
        multi=False,
        canonical_source_file="CAHOST:<host>",
        unlocks=(_CA_HOST,),
        absence_effects=(
            CapabilityEffect(
                capability_id=_CA_HOST,
                effect="unavailable",
                gap_class="ca_host_edges_unavailable_no_ca_hive",
                note="ManageCA/full-ESC resolution needs the CA host registry.",
            ),
            CapabilityEffect(
                capability_id=_ADCS_BASE,
                effect="degraded",
                gap_class="adcs_degraded_no_ca_hive",
                note="Base facts emit; ManageCA/full-ESC resolution missing.",
            ),
        ),
    ),
    ArtifactKind(
        id="additional_dc",
        label="Additional DC ntds.dit (other domain)",
        necessity="optional",
        pipeline_field=None,  # None: feeds multi-source additional_inputs, not a single field
        multi=True,
        canonical_source_file="ntds.dit:<dc>",
        unlocks=(_MULTI_DOM,),
        absence_effects=(
            CapabilityEffect(
                capability_id=_MULTI_DOM,
                effect="unavailable",
                gap_class="multi_domain_unavailable_single_dc",
                note=(
                    "One DC = single-source case; multi-domain/cross-DC per-source "
                    "views + opt-in merge activate with 2+ sources."
                ),
            ),
        ),
    ),
)


CAPABILITIES: Final[tuple[Capability, ...]] = (
    Capability(
        id=_CORE,
        label=(
            "Core directory graph (MemberOf, all ACL edges, Contains, GPLink, DCSync, "
            "delegation, RBCD, Read GMSA/LAPS, SIDHistory, trusts, node flags)"
        ),
        tier="A",
        requires_all=("ntds_dit",),
        degrades_without=(),
    ),
    Capability(
        id=_ADCS_BASE,
        label="ADCS base enrollment facts + CA/template topology (Tier-D composites)",
        tier="A/D",
        requires_all=("ntds_dit",),
        degrades_without=("system_hive", "ca_host_registry"),
    ),
    Capability(
        id=_SECRETS,
        label="Credential-material recovery (PEK/secret decryption -> encrypted refs)",
        tier="A",
        requires_all=("ntds_dit", "system_hive"),
        degrades_without=(),
    ),
    Capability(
        id=_ESC_DC,
        label="ESC9 / ESC10 decidability (DC cert-mapping / StrongCertificateBindingEnforcement)",
        tier="D",
        requires_all=("ntds_dit", "system_hive"),
        degrades_without=(),
    ),
    Capability(
        id=_GPO,
        label="GPO-driven edges (GPOLocalGroup->AdminTo, URA WRAITH:<Priv> edges, Registry.pol)",
        tier="B",
        requires_all=("ntds_dit", "sysvol"),
        degrades_without=(),
    ),
    Capability(
        id=_HOST_ADMINTO,
        label="Non-GPO local-admin / local-group membership (AdminTo)",
        tier="C",
        requires_all=("ntds_dit", "member_sam"),
        degrades_without=(),
    ),
    Capability(
        id=_CA_HOST,
        label="ManageCA, ManageCertificates + full ESC path resolution needing CA config",
        tier="C",
        requires_all=("ntds_dit", "ca_host_registry"),
        degrades_without=(),
    ),
    Capability(
        id=_MULTI_DOM,
        label="Cross-DC / multi-domain / multi-forest graph merge",
        tier="—",
        requires_all=("ntds_dit", "additional_dc"),
        degrades_without=(),
    ),
)


# --- fast indexes (built once from the frozen tables; deterministic) ----------
_KIND_BY_ID: Final[dict[str, ArtifactKind]] = {a.id: a for a in CATALOG}
_CAP_BY_ID: Final[dict[str, Capability]] = {c.id: c for c in CAPABILITIES}
#: ``(artifact_id, capability_id) -> CapabilityEffect`` for O(1) reason lookup.
_EFFECT_INDEX: Final[dict[tuple[str, str], CapabilityEffect]] = {
    (a.id, e.capability_id): e for a in CATALOG for e in a.absence_effects
}

#: The single required artifact id (``ntds_dit``); absent => analyze refused.
REQUIRED_KIND_IDS: Final[tuple[str, ...]] = tuple(
    a.id for a in CATALOG if a.necessity == "required"
)

#: Kinds with no wired consuming pass (``pipeline_field is None``). Uploading one
#: stores + registers it for provenance, but NO pass produces its capability yet;
#: the coverage function therefore treats these as absent for satisfaction (never
#: "pretend a pass exists", doc 14 §2a) while still reporting them ``uploaded``.
RESERVED_KIND_IDS: Final[frozenset[str]] = frozenset(
    a.id for a in CATALOG if a.pipeline_field is None
)

#: Multipart ``kind`` values accepted by the upload endpoint.
VALID_KIND_IDS: Final[frozenset[str]] = frozenset(a.id for a in CATALOG)


def artifact_kind(kind_id: str) -> ArtifactKind | None:
    """Return the :class:`ArtifactKind` for ``kind_id``, or ``None`` if unknown."""
    return _KIND_BY_ID.get(kind_id)


def capability(capability_id: str) -> Capability | None:
    """Return the :class:`Capability` for ``capability_id``, or ``None``."""
    return _CAP_BY_ID.get(capability_id)


def absence_effect(artifact_id: str, capability_id: str) -> CapabilityEffect | None:
    """Return the effect of ``artifact_id`` being absent on ``capability_id``.

    Inputs:
        artifact_id: a :data:`CATALOG` artifact id.
        capability_id: a :data:`CAPABILITIES` capability id.

    Returns:
        The declared :class:`CapabilityEffect`, or ``None`` if the artifact's
        absence has no declared effect on that capability (e.g. ``ntds_dit``,
        whose absence is a hard error rather than a per-capability effect).

    Failure modes:
        None (pure dict lookup; never raises).
    """
    return _EFFECT_INDEX.get((artifact_id, capability_id))


# --- safety bounds (doc 14 §5): per-kind size caps + content-magic sniff -------
_GIB: Final[int] = 1024 * 1024 * 1024
_MIB: Final[int] = 1024 * 1024

#: Per-kind maximum upload size in bytes, enforced WHILE streaming (413 on
#: overflow). Values from doc 14 §5 (ntds 10 GiB, hives 256 MiB, SYSVOL zip
#: 2 GiB); reserved kinds reuse the analogous cap.
MAX_UPLOAD_BYTES: Final[dict[str, int]] = {
    "ntds_dit": 10 * _GIB,
    "system_hive": 256 * _MIB,
    "sysvol": 2 * _GIB,
    "member_sam": 256 * _MIB,
    "ca_host_registry": 256 * _MIB,
    "additional_dc": 10 * _GIB,
}

#: Cap for a ``member_sam`` companion host SYSTEM hive (same class as a hive).
MAX_COMPANION_SYSTEM_BYTES: Final[int] = 256 * _MIB

#: Magic-sniff family per kind (doc 14 §5). A guard, not a trust decision; the
#: real parser still validates. ``ese`` = ESE page header, ``regf`` = registry
#: hive, ``zip`` = SYSVOL archive.
SniffKind = Literal["ese", "regf", "zip"]
MAGIC_SNIFF: Final[dict[str, SniffKind]] = {
    "ntds_dit": "ese",
    "system_hive": "regf",
    "sysvol": "zip",
    "member_sam": "regf",
    "ca_host_registry": "regf",
    "additional_dc": "ese",
}

#: ESE database ``ulMagic`` (0x89ABCDEF) at byte offset 4, little-endian.
ESE_MAGIC_OFFSET: Final[int] = 4
ESE_MAGIC: Final[bytes] = b"\xef\xcd\xab\x89"
#: Windows registry hive signature at offset 0.
REGF_MAGIC: Final[bytes] = b"regf"
#: ZIP local-file-header / empty-archive signatures at offset 0.
ZIP_MAGICS: Final[tuple[bytes, ...]] = (b"PK\x03\x04", b"PK\x05\x06")

#: SYSVOL zip extraction resource caps (zip-bomb / zip-slip robustness, §5/§7).
SYSVOL_MAX_MEMBERS: Final[int] = 100_000
SYSVOL_MAX_TOTAL_UNCOMPRESSED_BYTES: Final[int] = 2 * _GIB


__all__ = [
    "Capability",
    "CapabilityEffect",
    "ArtifactKind",
    "Necessity",
    "Effect",
    "SniffKind",
    "CATALOG",
    "CAPABILITIES",
    "REQUIRED_KIND_IDS",
    "RESERVED_KIND_IDS",
    "VALID_KIND_IDS",
    "NO_NTDS_GAP_CLASS",
    "MAX_UPLOAD_BYTES",
    "MAX_COMPANION_SYSTEM_BYTES",
    "MAGIC_SNIFF",
    "ESE_MAGIC_OFFSET",
    "ESE_MAGIC",
    "REGF_MAGIC",
    "ZIP_MAGICS",
    "SYSVOL_MAX_MEMBERS",
    "SYSVOL_MAX_TOTAL_UNCOMPRESSED_BYTES",
    "artifact_kind",
    "capability",
    "absence_effect",
]
