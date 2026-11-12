"""Identity, scoping and DN reconstruction for Module 3 (research items 3, 5, 6).

Three concerns, all pure/deterministic:

* **``node_id_for_sid``** — the SID -> ``node_id`` resolver shared with M5. Real
  domain objects key off their ``objectGUID`` via 2b's ``compute_node_id``;
  SID-only stubs (well-known/BUILTIN SIDs, FSP foreign SIDs) key off this
  helper. Well-known/BUILTIN SIDs are **domain-scoped** (``forest || domain ||
  sid``) to avoid the cross-domain collision BloodHound also guards against;
  domain-specific ``S-1-5-21-...`` SIDs are globally unique and key off
  ``forest || sid``.
* **Directory index + DN reconstruction** — NTDS stores an RDN per object, not a
  full DN. A first pass builds ``dnt -> entry``; DNs and ``parent_node_id`` are
  then reconstructed deterministically by walking ``parent_dnt`` to the NC head.
* **Domain/forest scoping** — the ``domainDNS`` object's ``objectSid`` is the
  ``domain_id``; ``domain_fqdn`` comes from its ``DC=`` component chain; the
  ``forest_id`` is resolved from ``CaseConfig.forest_id_map`` (deterministic
  fallback derives it from the domain SID).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from wraith.common.determinism import sha256_hex, stable_id

#: The synthetic NTDS tree-root sentinel RDN; the parent walk stops here.
_ROOT_SENTINEL: str = "$ROOT_OBJECT$"

#: Provenance markers for synthetic well-known-SID stub Principals.
WELLKNOWN_SOURCE_FILE: str = "synthetic:wellknown"

#: Deterministic NON-real ``image_sha256`` sentinel for synthetic (objectless)
#: stub-Principal provenance: a valid 64-hex value that claims NO acquired
#: artifact's real SHA-256. THE single source of truth — M3 (normalizer) and M5
#: (edge engine) both import this so a stub minted by either for the same SID has
#: byte-identical provenance and therefore the same ``node_id`` (the cross-module
#: alignment guarantee must not rest on two copies of the literal).
WELLKNOWN_IMAGE_SHA256: str = sha256_hex(b"wraith:synthetic:wellknown")


def wellknown_source_object_id(sid: str) -> str:
    """Return the synthetic ``source_object_id`` for an objectless stub Principal.

    Inputs:
        sid: the SID with no backing object.

    Returns:
        The canonical ``synthetic:wellknown:<sid>`` identifier (shared by M3 + M5).

    Failure modes:
        Never raises.
    """
    return f"synthetic:wellknown:{sid}"


#: Public well-known SID -> (canonical display name, principal_type). Reusable
#: [MS-DTYP] facts. Service identities (S-1-5-18/19/20) type as ``User``; the
#: S-1-5-32 aliases and the broad authentication groups type as ``Group``.
WELL_KNOWN_SIDS: Mapping[str, tuple[str, str]] = {
    "S-1-0-0": ("NULL SID", "Group"),
    "S-1-1-0": ("Everyone", "Group"),
    "S-1-2-0": ("LOCAL", "Group"),
    "S-1-2-1": ("CONSOLE LOGON", "Group"),
    "S-1-3-0": ("CREATOR OWNER", "Group"),
    "S-1-3-1": ("CREATOR GROUP", "Group"),
    "S-1-3-4": ("OWNER RIGHTS", "Group"),
    "S-1-5-1": ("DIALUP", "Group"),
    "S-1-5-2": ("NETWORK", "Group"),
    "S-1-5-3": ("BATCH", "Group"),
    "S-1-5-4": ("INTERACTIVE", "Group"),
    "S-1-5-6": ("SERVICE", "Group"),
    "S-1-5-7": ("ANONYMOUS LOGON", "Group"),
    "S-1-5-9": ("ENTERPRISE DOMAIN CONTROLLERS", "Group"),
    "S-1-5-10": ("SELF (PRINCIPAL SELF)", "Group"),
    "S-1-5-11": ("Authenticated Users", "Group"),
    "S-1-5-12": ("RESTRICTED CODE", "Group"),
    "S-1-5-13": ("TERMINAL SERVER USER", "Group"),
    "S-1-5-14": ("REMOTE INTERACTIVE LOGON", "Group"),
    "S-1-5-15": ("THIS ORGANIZATION", "Group"),
    "S-1-5-17": ("IUSR", "Group"),
    "S-1-5-18": ("LOCAL SYSTEM", "User"),
    "S-1-5-19": ("LOCAL SERVICE", "User"),
    "S-1-5-20": ("NETWORK SERVICE", "User"),
    "S-1-5-32-544": ("BUILTIN\\Administrators", "Group"),
    "S-1-5-32-545": ("BUILTIN\\Users", "Group"),
    "S-1-5-32-546": ("BUILTIN\\Guests", "Group"),
    "S-1-5-32-547": ("BUILTIN\\Power Users", "Group"),
    "S-1-5-32-548": ("BUILTIN\\Account Operators", "Group"),
    "S-1-5-32-549": ("BUILTIN\\Server Operators", "Group"),
    "S-1-5-32-550": ("BUILTIN\\Print Operators", "Group"),
    "S-1-5-32-551": ("BUILTIN\\Backup Operators", "Group"),
    "S-1-5-32-552": ("BUILTIN\\Replicators", "Group"),
    "S-1-5-32-554": ("BUILTIN\\Pre-Windows 2000 Compatible Access", "Group"),
    "S-1-5-32-555": ("BUILTIN\\Remote Desktop Users", "Group"),
    "S-1-5-32-556": ("BUILTIN\\Network Configuration Operators", "Group"),
    "S-1-5-32-557": ("BUILTIN\\Incoming Forest Trust Builders", "Group"),
    "S-1-5-32-558": ("BUILTIN\\Performance Monitor Users", "Group"),
    "S-1-5-32-559": ("BUILTIN\\Performance Log Users", "Group"),
    "S-1-5-32-560": ("BUILTIN\\Windows Authorization Access Group", "Group"),
    "S-1-5-32-561": ("BUILTIN\\Terminal Server License Servers", "Group"),
    "S-1-5-32-562": ("BUILTIN\\Distributed COM Users", "Group"),
    "S-1-5-32-568": ("BUILTIN\\IIS_IUSRS", "Group"),
    "S-1-5-32-569": ("BUILTIN\\Cryptographic Operators", "Group"),
    "S-1-5-32-573": ("BUILTIN\\Event Log Readers", "Group"),
    "S-1-5-32-574": ("BUILTIN\\Certificate Service DCOM Access", "Group"),
    "S-1-5-32-575": ("BUILTIN\\RDS Remote Access Servers", "Group"),
    "S-1-5-32-576": ("BUILTIN\\RDS Endpoint Servers", "Group"),
    "S-1-5-32-577": ("BUILTIN\\RDS Management Servers", "Group"),
    "S-1-5-32-578": ("BUILTIN\\Hyper-V Administrators", "Group"),
    "S-1-5-32-579": ("BUILTIN\\Access Control Assistance Operators", "Group"),
    "S-1-5-32-580": ("BUILTIN\\Remote Management Users", "Group"),
}


def is_domain_specific_sid(sid: str) -> bool:
    """Return whether ``sid`` is a domain-specific ``S-1-5-21-...`` SID.

    Such SIDs embed the unique domain identifier so they are globally unique and
    keyed off ``forest || sid`` (not domain-scoped). All other SIDs
    (``S-1-5-32-*`` BUILTIN, ``S-1-1-0``, service identities, ...) are identical
    across domains and MUST be domain-scoped.

    Inputs:
        sid: a SID string.

    Returns:
        ``True`` if it is an ``S-1-5-21-`` domain SID (with or without a RID).

    Failure modes:
        Never raises; a malformed string returns ``False``.
    """
    parts = sid.split("-")
    return len(parts) >= 5 and parts[:4] == ["S", "1", "5", "21"]


def node_id_for_sid(forest_id: str, domain_id: str | None, sid: str) -> str:
    """Resolve a SID to its canonical ``node_id`` (the contract shared with M5).

    Domain-specific ``S-1-5-21-...`` SIDs hash as ``stable_id(forest_id, sid)``
    (globally unique, matching :func:`compute_node_id`'s SID-fallback). Every
    other SID (well-known/BUILTIN/FSP foreign SID) is domain-scoped as
    ``stable_id(forest_id, domain_id, sid)`` so two domains' ``BUILTIN\\
    Administrators`` do not collide.

    **M5 MUST call this exact function** to resolve an ACE/primaryGroup SID to
    the node M3 minted (real principals are also discoverable by their
    ``object_sid`` column; objectless SIDs resolve here to the stub M3
    materialized).

    Inputs:
        forest_id: the scoping forest id.
        domain_id: the scoping domain id (the ``domainDNS`` SID); may be ``None``
            only in degenerate inputs — then the well-known branch uses ``""``.
        sid: the SID string to resolve.

    Returns:
        A 64-hex ``node_id``.

    Failure modes:
        Never raises.
    """
    if is_domain_specific_sid(sid):
        return stable_id(forest_id, sid)
    return stable_id(forest_id, domain_id or "", sid)


def resolve_forest_id(
    forest_id_map: Mapping[str, str],
    domain_fqdn: str | None,
    domain_sid: str | None,
) -> str:
    """Resolve the scoping ``forest_id`` (research item 5), deterministically.

    Lookup order: an exact ``forest_id_map`` hit on ``domain_fqdn`` (then its
    NetBIOS-style leading label); else, if the map has exactly one entry, that
    single configured forest (v1 single-forest); else a deterministic derivation
    from the domain SID (``stable_id("forest", domain_sid)``) so a run is never
    blocked on configuration.

    Inputs:
        forest_id_map: ``CaseConfig.forest_id_map`` (``{domain_hint: forest_id}``).
        domain_fqdn: the resolved domain FQDN, or ``None``.
        domain_sid: the resolved domain SID, or ``None``.

    Returns:
        A stable ``forest_id`` string.

    Failure modes:
        Raises ``ValueError`` only if neither a map entry nor a domain SID is
        available (nothing to scope to).
    """
    if domain_fqdn:
        if domain_fqdn in forest_id_map:
            return forest_id_map[domain_fqdn]
        netbios = domain_fqdn.split(".")[0]
        if netbios in forest_id_map:
            return forest_id_map[netbios]
    if len(forest_id_map) == 1:
        return next(iter(forest_id_map.values()))
    if domain_sid:
        return stable_id("forest", domain_sid)
    raise ValueError("cannot resolve forest_id: no forest_id_map entry and no domain SID")


@dataclass(frozen=True)
class IndexEntry:
    """One object's structural facts needed for DN/parent reconstruction."""

    dnt: int
    parent_dnt: int | None
    rdn: str | None
    class_names: frozenset[str]
    node_id: str | None
    object_sid: str | None
    object_guid: str | None


@dataclass
class DirectoryIndex:
    """First-pass ``dnt -> IndexEntry`` index for DN/parent reconstruction.

    Built by streaming the objects once; then :meth:`reconstruct_dn` and
    :meth:`parent_node_id` resolve the tree deterministically without trusting
    any stored DN string.
    """

    by_dnt: dict[int, IndexEntry] = field(default_factory=dict)

    def add(self, entry: IndexEntry) -> None:
        """Register one object's :class:`IndexEntry` (keyed by DNT)."""
        self.by_dnt[entry.dnt] = entry

    def parent_node_id(self, dnt: int) -> str | None:
        """Return the ``node_id`` of ``dnt``'s parent, or ``None`` if unresolved."""
        entry = self.by_dnt.get(dnt)
        if entry is None or entry.parent_dnt is None:
            return None
        parent = self.by_dnt.get(entry.parent_dnt)
        return parent.node_id if parent is not None else None

    def parent_resolved(self, dnt: int) -> bool:
        """Return whether ``dnt``'s ``parent_dnt`` points at a known object.

        A top-level object whose parent is the NC root sentinel counts as
        resolved; only a dangling parent (present ``parent_dnt`` absent from the
        index) is an orphan.
        """
        entry = self.by_dnt.get(dnt)
        if entry is None or entry.parent_dnt is None:
            return True
        return entry.parent_dnt in self.by_dnt

    def _walk(self, dnt: int) -> list[IndexEntry]:
        """Collect entries child-first from ``dnt`` up to (excluding) the NC root."""
        chain: list[IndexEntry] = []
        seen: set[int] = set()
        cur: int | None = dnt
        while cur is not None and cur in self.by_dnt and cur not in seen:
            seen.add(cur)
            entry = self.by_dnt[cur]
            if entry.rdn == _ROOT_SENTINEL:
                break
            chain.append(entry)
            cur = entry.parent_dnt
        return chain

    def reconstruct_dn(self, dnt: int) -> str | None:
        """Reconstruct an object's distinguished name by walking ``parent_dnt``.

        RDN prefixes: ``domainDNS``/``domain`` -> ``DC``; ``organizationalUnit``
        -> ``OU``; otherwise ``CN``. An unknown-class node that sits inside the
        ``DC=`` suffix (its child was already a ``DC`` component) is also treated
        as ``DC`` so the NC head reconstructs correctly (e.g. the synthetic
        ``DC=local`` placeholder observed in evidence).

        Inputs:
            dnt: the object's DNT.

        Returns:
            The reconstructed DN string, or ``None`` if the object (or its RDN)
            is unknown.

        Failure modes:
            Never raises; a cycle is broken and the partial DN returned.
        """
        chain = self._walk(dnt)
        if not chain or chain[0].rdn is None:
            return None
        in_dc = False
        parts: list[str] = []
        for entry in chain:
            rdn = entry.rdn
            if rdn is None:
                continue
            classes = entry.class_names
            if "domainDNS" in classes or "domain" in classes:
                prefix = "DC"
                in_dc = True
            elif "organizationalUnit" in classes:
                prefix = "OU"
            elif not classes and in_dc:
                prefix = "DC"
            else:
                prefix = "CN"
            parts.append(f"{prefix}={rdn}")
        return ",".join(parts)

    def domain_fqdn_for(self, dnt: int) -> str | None:
        """Return the DNS FQDN for the ``domainDNS`` object ``dnt`` (``DC=`` chain).

        Walks the object + ancestors, collecting the ``DC=`` component RDNs and
        joining them lowercased with dots (``DC=C137,DC=local`` -> ``c137.local``).

        Inputs:
            dnt: the ``domainDNS`` object's DNT.

        Returns:
            The FQDN, or ``None`` if no ``DC`` components were found.

        Failure modes:
            Never raises.
        """
        chain = self._walk(dnt)
        in_dc = False
        labels: list[str] = []
        for entry in chain:
            classes = entry.class_names
            if "domainDNS" in classes or "domain" in classes:
                in_dc = True
                if entry.rdn is not None:
                    labels.append(entry.rdn)
            elif not classes and in_dc and entry.rdn is not None:
                labels.append(entry.rdn)
        return ".".join(label.lower() for label in labels) if labels else None
