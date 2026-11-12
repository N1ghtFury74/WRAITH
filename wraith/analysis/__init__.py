"""WRAITH analysis passes — inferred composites over the confirmed graph.

Currently hosts the ADCS ESC attack-path composition (Phase 2): a dedicated
cross-object pass that reads the confirmed M5 base edges + Phase-1 ADCS topology
edges + the M4 ``effective_membership`` closure + template ``pki_flags`` + the
imaged DC's SYSTEM-hive config, and emits the ESC composites as ``inferred``
edges. See :mod:`wraith.analysis.adcs_esc`.
"""

from __future__ import annotations

from wraith.analysis.adcs_esc import (
    ABSENT_CA_HOST_FACTS,
    KIND_ENROLL_ON_BEHALF_OF,
    KIND_ESC1,
    KIND_ESC3,
    KIND_ESC4,
    KIND_ESC6A,
    KIND_ESC6B,
    KIND_ESC9,
    KIND_ESC10A,
    KIND_ESC10B,
    KIND_ESC13,
    KIND_ESC15,
    KIND_GOLDEN_CERT,
    KIND_MANAGE_CA,
    KIND_MANAGE_CERTIFICATES,
    AdcsEscResult,
    CaHostFacts,
    CaNodeFinding,
    CaRegistryFacts,
    DcConfigFlags,
    DcomRestrictions,
    EscTemplate,
    compute_adcs_esc,
    decode_template,
    effective_ekus,
    is_high_priv_sid,
    normalize_ca_name,
    read_dc_config_flags,
    run_adcs_esc,
)
from wraith.analysis.ca_findings_store import persist_ca_node_findings
from wraith.analysis.ca_host_facts import build_ca_host_facts, parse_ca_security

__all__ = [
    "ABSENT_CA_HOST_FACTS",
    "KIND_ENROLL_ON_BEHALF_OF",
    "KIND_ESC1",
    "KIND_ESC3",
    "KIND_ESC4",
    "KIND_ESC6A",
    "KIND_ESC6B",
    "KIND_ESC9",
    "KIND_ESC10A",
    "KIND_ESC10B",
    "KIND_ESC13",
    "KIND_ESC15",
    "KIND_GOLDEN_CERT",
    "KIND_MANAGE_CA",
    "KIND_MANAGE_CERTIFICATES",
    "AdcsEscResult",
    "CaHostFacts",
    "CaNodeFinding",
    "CaRegistryFacts",
    "DcConfigFlags",
    "DcomRestrictions",
    "EscTemplate",
    "build_ca_host_facts",
    "compute_adcs_esc",
    "decode_template",
    "effective_ekus",
    "is_high_priv_sid",
    "normalize_ca_name",
    "parse_ca_security",
    "persist_ca_node_findings",
    "read_dc_config_flags",
    "run_adcs_esc",
]
