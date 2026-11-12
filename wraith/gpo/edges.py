"""GPO-derived §4 edge builders — all ``confidence="inferred"`` (schema §4).

Two families, both FLAT ``source = principal -> target = computer`` with no
intermediate node (BloodHound ``AdminTo`` direction; the GPO and the OU scope
are HOW the edge set is computed, not nodes on the edge):

* **Local-group edges** (BloodHound-native): a restricted-group / GPP member of a
  well-known local group becomes ``AdminTo`` / ``CanRDP`` / ``ExecuteDCOM`` /
  ``CanPSRemote`` on every affected computer. ``derivation = GPO:<Kind>``.
* **Privilege edges** (WRAITH-native; NOT BloodHound-native — kind carries the
  :data:`~wraith.gpo.constants.WRAITH_NATIVE_KIND_PREFIX` so M6 export never
  claims BH parity): a high-value ``Se*Privilege`` holder that is NOT already
  admin-baseline becomes ``WRAITH:<Priv>`` on every affected computer.
  ``derivation = GPO:<Priv>``.

All builders are pure; the engine does the DB I/O and the mint-on-miss SID
resolution (reusing the M5 :class:`~wraith.edges.acl.NodeResolver`).
"""

from __future__ import annotations

from collections.abc import Iterable

from wraith.common.determinism import stable_id
from wraith.edges.models import EdgeRow
from wraith.gpo.constants import CONFIDENCE_INFERRED, WRAITH_NATIVE_KIND_PREFIX
from wraith.provenance.models import ProvenanceStruct

#: ``derivation`` tag prefix for every GPO-derived edge (``GPO:AdminTo``,
#: ``GPO:SeBackupPrivilege`` ...).
DERIVATION_PREFIX: str = "GPO:"


def _gpo_edge(
    kind: str,
    derivation: str,
    source_node_id: str,
    target_node_id: str,
    provenance: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> EdgeRow:
    """Build one inferred GPO edge (NULL mask/object_type_guid, is_inherited None).

    ``is_inherited`` is ``None`` (a GPO push is not an ACE, so the inherited-vs-
    explicit distinction does not apply) and ``confidence`` is ``inferred``.
    """
    forest_id, domain_id, domain_fqdn = scoping
    return EdgeRow(
        edge_id=stable_id(kind, source_node_id, target_node_id, derivation),
        kind=kind,
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        is_inherited=None,
        derivation=derivation,
        access_mask=None,
        object_type_guid=None,
        confidence=CONFIDENCE_INFERRED,
        forest_id=forest_id,
        domain_id=domain_id,
        domain_fqdn=domain_fqdn,
        provenance=provenance,
    )


def build_local_group_edges(
    member_node_id: str,
    kind: str,
    affected_computer_ids: Iterable[str],
    provenance: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> list[EdgeRow]:
    """Build local-group edges ``member -> <kind> -> computer`` for one member.

    Inputs:
        member_node_id: the resolved principal pushed into the local group.
        kind: the edge kind from the alias-SID map (``AdminTo`` / ``CanRDP`` /
            ``ExecuteDCOM`` / ``CanPSRemote``).
        affected_computer_ids: the GPO's affected computer node ids.
        provenance: the ``[Group Membership]`` / GPP fact's provenance.
        scoping: the ``(forest_id, domain_id, domain_fqdn)`` block.

    Returns:
        One edge per affected computer (reflexive member==computer skipped).

    Failure modes:
        Never raises.
    """
    derivation = f"{DERIVATION_PREFIX}{kind}"
    edges: list[EdgeRow] = []
    for computer_id in affected_computer_ids:
        if computer_id == member_node_id:
            continue
        edges.append(_gpo_edge(kind, derivation, member_node_id, computer_id, provenance, scoping))
    return edges


def privilege_edge_kind(privilege: str) -> str:
    """Return the WRAITH-native edge kind for a privilege (``WRAITH:<Priv>``)."""
    return f"{WRAITH_NATIVE_KIND_PREFIX}{privilege}"


def build_privilege_edges(
    holder_node_id: str,
    privilege: str,
    affected_computer_ids: Iterable[str],
    provenance: ProvenanceStruct,
    scoping: tuple[str, str | None, str | None],
) -> list[EdgeRow]:
    """Build WRAITH-native privilege edges ``holder -> WRAITH:<Priv> -> computer``.

    Inputs:
        holder_node_id: the resolved principal granted the privilege.
        privilege: the privilege name (e.g. ``SeBackupPrivilege``).
        affected_computer_ids: the GPO's affected computer node ids.
        provenance: the ``[Privilege Rights]`` fact's provenance.
        scoping: the ``(forest_id, domain_id, domain_fqdn)`` block.

    Returns:
        One edge per affected computer (reflexive holder==computer skipped). The
        kind is ``WRAITH:<Priv>`` (non-BH-native marker); derivation ``GPO:<Priv>``.

    Failure modes:
        Never raises.
    """
    kind = privilege_edge_kind(privilege)
    derivation = f"{DERIVATION_PREFIX}{privilege}"
    edges: list[EdgeRow] = []
    for computer_id in affected_computer_ids:
        if computer_id == holder_node_id:
            continue
        edges.append(_gpo_edge(kind, derivation, holder_node_id, computer_id, provenance, scoping))
    return edges
