<div align="center">

# WRAITH

**Know what the attacker knows.**

Offline, dead-disk **Active Directory relationship mapper** for authorized penetration testing and incident response.

[Engineering deep-dive](https://n1ghtfury74.github.io/blog/2026/11/05/building-wraith/) · Offline · Provenance-first · Deterministic

</div>

---

## What it is

Hand WRAITH the forensic artifacts from a domain controller — `ntds.dit`, the `SYSTEM` hive, and a copy of `SYSVOL` — and it reconstructs the domain's **privilege and attack graph entirely offline**, with **zero packets to any target**. It answers the questions that shape a hunt or an IR engagement: *who can reach Tier-0, what a given principal controls, and where the attack paths run* — before you touch the live estate.

BloodHound and SharpHound need a live, reachable directory to collect from. WRAITH closes the other case: a **dead disk image**, an air-gapped lab, or seized evidence where live collection is impossible or forbidden. It reuses the *ideas* of the attacker-lens graph and the *mature libraries* for the hard parsing — and builds the same model natively for the offline case.

> **BloodHound is one swappable export adapter. The canonical graph is the product.**

## What it produces

- A **capability graph** — identities, groups, ACLs, GPO application, AD CS topology, and host-level privilege, as "who can do what to whom."
- **Per-entity dossiers** — the full inbound/outbound control picture for any principal, with paths to Tier-0, rendered in the web UI or exported to **PDF**.
- **Risk findings** — Tier-0 reachability, dangerous ACLs, delegation, AD CS escalation (ESC) exposure.
- **Forensic provenance on every entity and edge** — `{source file, image SHA-256, source object id, directory timestamp}`, attached at creation.
- A **BloodHound CE export** for analysts who want the reference graph UI.

## What it maps

| Area | Edges / facts |
|---|---|
| **Core directory** | `MemberOf`, all ACL edges (`GenericAll`/`WriteDacl`/`WriteOwner`/`AllExtendedRights`/…), `Contains`, `GPLink`, `DCSync`, delegation (unconstrained / constrained / RBCD), `ReadGMSAPassword`, `ReadLAPSPassword`, `HasSIDHistory`, domain/forest **trusts**, node flags |
| **GPO / SYSVOL** | GPO-pushed local-group membership (`AdminTo` and friends), user-rights assignments, `Registry.pol` |
| **Host SAM** | Non-GPO local privilege per machine — `AdminTo`, `CanRDP`, `ExecuteDCOM`, `CanPSRemote` — read from each member host's SAM |
| **AD CS** | Certificate-template topology, enrollment rights, **ESC1–ESC16** where decidable; from the CA host registry: `ManageCA` / `ManageCertificates`, EDITF/InterfaceFlags (ESC6/11/16), and machine-wide DCOM posture |
| **Multi-source** | Multiple DCs / domains / forests with **per-source views first**, an **opt-in merge** that produces an honest **divergence ledger** (deleted-on-one-DC, lingering objects, un-replicated secrets), and cross-domain trust / FSP / SID-history edges |

## The guarantees (non-negotiable)

- **Offline.** No component initiates network egress at runtime. Zero packets to any target.
- **Provenance everywhere.** No fact without its source. Every entity and edge is traceable to the artifact it came from.
- **Secrets, handled.** Credential material is encrypted at rest in the case workspace, redacted by default, and **never logged in plaintext**.
- **Deterministic.** Identical inputs produce identical outputs.
- **Honest coverage.** Missing evidence is a **counted, surfaced gap** — never a silent wrong answer. The UI tells you exactly what each artifact unlocks and what its absence costs.
- **Authorized use only.** WRAITH operates solely on artifacts the operator is lawfully authorized to possess.

## Quick start (Docker)

```bash
docker compose up --build
# WRAITH is now at http://localhost:8000
```

Open the web UI, create a case, drop in a capture folder (or upload `ntds.dit` + the `SYSTEM` hive and any optional artifacts), run the analysis, and explore the graph, dossiers, and risk. Everything runs offline.

To also bring up the optional Neo4j + BloodHound CE reference stack:

```bash
docker compose --profile bloodhound up --build
```

## Architecture

- **Engine** (`wraith/`) — acquisition · ESE/NTDS parsing · security-descriptor & secret decryption · normalization · membership closure · the edge engine · GPO/SYSVOL · AD CS · host SAM · multi-source reconciliation · BloodHound export · dossier/PDF · provenance.
- **Store** — DuckDB as the canonical, analytics-ready store (Parquet-friendly); a capability graph projected over it with NetworkX for pathfinding.
- **Interfaces** — FastAPI + Uvicorn API (with a live WebSocket progress channel), a React/Vite web UI, and a Typer CLI.
- **Reference UI (optional)** — Neo4j + BloodHound CE via `docker-compose`.

Correctness-critical formats are delegated to battle-tested libraries (ESE/NTDS, security descriptors, PEK/secret decryption, registry hives, X.509) — never hand-rolled, never copied.

## Engineering write-up

A module-by-module deep-dive on how WRAITH was built — the parsing chain, the edge engine, the offline and provenance guarantees, and the testing discipline:

**→ [Building WRAITH](https://n1ghtfury74.github.io/blog/2026/11/05/building-wraith/)**

## Authorized use only

WRAITH is for lawful, authorized security work only — authorized penetration testing, incident response, and research on evidence you are permitted to possess. **No live collection. No password cracking. On-prem AD only.** You are responsible for operating within your authorization and the law.

## License

[Apache-2.0](LICENSE).
