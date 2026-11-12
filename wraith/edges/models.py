"""Row dataclasses + the result shape for Module 4 (the Membership Resolver).

:class:`EdgeRow` mirrors the FROZEN §4 ``edge`` table column order exactly (see
``wraith/model/store.py``); :class:`EffectiveMembershipRow` mirrors the derived
``effective_membership`` table. Both expose ``to_db_values`` returning the
positional tuple the writer binds to ``executemany``. Only the embedded
provenance struct is normalized at write time (naive-UTC ``directory_timestamp``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from wraith.normalize.decoders import to_naive_utc
from wraith.provenance.models import ProvenanceStruct


def _provenance_struct_value(provenance: ProvenanceStruct) -> dict[str, object]:
    """Encode a :class:`ProvenanceStruct` as the DuckDB provenance STRUCT dict.

    Mirrors the normalizer's encoder so an edge row's provenance column is
    byte-identical in shape to every entity row's.
    """
    return {
        "source_file": provenance.source_file,
        "image_sha256": provenance.image_sha256,
        "source_object_id": provenance.source_object_id,
        "directory_timestamp": to_naive_utc(provenance.directory_timestamp),
        "ingest_run_id": provenance.ingest_run_id,
    }


@dataclass(frozen=True)
class EdgeRow:
    """One FROZEN §4 ``edge`` row.

    For a ``MemberOf`` edge: ``source_node_id`` is the member, ``target_node_id``
    is the group (BloodHound's member->group direction, traversable), ``kind`` is
    ``"MemberOf"``, ``is_inherited`` is ``False`` (membership is not an ACE),
    ``access_mask``/``object_type_guid`` are ``None``, and ``derivation`` is one
    of ``LINK:member`` / ``SYNTH:primarygroup`` / ``SYNTH:specialidentity``.
    ``edge_id`` is ``stable_id(kind, source, target, derivation)``.
    """

    edge_id: str
    kind: str
    source_node_id: str
    target_node_id: str
    is_inherited: bool | None
    derivation: str | None
    access_mask: int | None
    object_type_guid: str | None
    confidence: str | None
    forest_id: str
    domain_id: str | None
    domain_fqdn: str | None
    provenance: ProvenanceStruct

    def to_db_values(self) -> tuple[object, ...]:
        """Return the positional insert tuple for the ``edge`` table."""
        return (
            self.edge_id,
            self.kind,
            self.source_node_id,
            self.target_node_id,
            self.is_inherited,
            self.derivation,
            self.access_mask,
            self.object_type_guid,
            self.confidence,
            self.forest_id,
            self.domain_id,
            self.domain_fqdn,
            _provenance_struct_value(self.provenance),
        )


@dataclass(frozen=True)
class EffectiveMembershipRow:
    """One ``effective_membership`` row (effective member -> group), node-keyed."""

    member_node_id: str
    group_node_id: str
    forest_id: str
    domain_id: str | None

    def to_db_values(self) -> tuple[object, ...]:
        """Return the positional insert tuple for ``effective_membership``."""
        return (
            self.member_node_id,
            self.group_node_id,
            self.forest_id,
            self.domain_id,
        )


@dataclass(frozen=True)
class MembershipResult:
    """The outcome of a membership-resolution run (counts only; never secrets).

    Attributes:
        member_link_base: the ``member`` attribute's resolved ``link_base``
            (``linkID >> 1``), or ``None`` if the schema did not surface it (then
            no stored-link edges were produced — a surfaced gap).
        edges_direct: direct ``MemberOf`` edges from stored links (``LINK:member``).
        edges_primarygroup: synthesized ``SYNTH:primarygroup`` edges.
        edges_synthetic: synthesized ``SYNTH:specialidentity`` edges.
        edges_total: distinct edge rows written (deduped by ``edge_id``).
        effective_pairs: rows written to ``effective_membership``.
        coverage_counts: the run's coverage counters snapshot.
        skip_counts: the run's skip/gap counters snapshot.
    """

    member_link_base: int | None
    edges_direct: int
    edges_primarygroup: int
    edges_synthetic: int
    edges_total: int
    effective_pairs: int
    coverage_counts: Mapping[str, int]
    skip_counts: Mapping[str, int]
