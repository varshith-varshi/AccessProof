"""Canonical, machine-readable support registry for AccessProof Core.

One static source of truth replaces scattered "supported" claims in docs, UI and
release notes. Every state is paired with the evidence level actually obtained
in this repository, not with an aspirational label. A mocked provider response
can never be promoted to a live-provider state here.
"""
from __future__ import annotations

import csv
import io
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable

from packages.rag_sdk.registry import adapter_registry


CAPABILITY_REGISTRY_SCHEMA = "accessproof.capability_registry/v1"
RELEASE_GATE_SCHEMA = "accessproof.release_gate/v1"


class SupportState(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"


class EvidenceLevel(str, Enum):
    UNIT_VERIFIED = "UNIT_VERIFIED"
    LOCAL_INTEGRATION_VERIFIED = "LOCAL_INTEGRATION_VERIFIED"
    CONTRACT_SIMULATED = "CONTRACT_SIMULATED"
    LIVE_PROVIDER_VERIFIED = "LIVE_PROVIDER_VERIFIED"
    INDEPENDENT_CUSTOMER_VERIFIED = "INDEPENDENT_CUSTOMER_VERIFIED"
    STAGING_VERIFIED = "STAGING_VERIFIED"
    PRODUCTION_OBSERVED = "PRODUCTION_OBSERVED"


# Evidence required before a capability may use a given state. Support cannot
# outrun evidence: this is the machine-enforced part of the registry.
_MINIMUM_EVIDENCE = {
    SupportState.SUPPORTED: {
        EvidenceLevel.UNIT_VERIFIED,
        EvidenceLevel.LOCAL_INTEGRATION_VERIFIED,
        EvidenceLevel.CONTRACT_SIMULATED,
        EvidenceLevel.LIVE_PROVIDER_VERIFIED,
        EvidenceLevel.INDEPENDENT_CUSTOMER_VERIFIED,
        EvidenceLevel.STAGING_VERIFIED,
        EvidenceLevel.PRODUCTION_OBSERVED,
    },
    SupportState.PARTIAL: {
        EvidenceLevel.UNIT_VERIFIED,
        EvidenceLevel.LOCAL_INTEGRATION_VERIFIED,
        EvidenceLevel.CONTRACT_SIMULATED,
        EvidenceLevel.LIVE_PROVIDER_VERIFIED,
        EvidenceLevel.INDEPENDENT_CUSTOMER_VERIFIED,
        EvidenceLevel.STAGING_VERIFIED,
        EvidenceLevel.PRODUCTION_OBSERVED,
    },
    SupportState.UNKNOWN: set(),
    SupportState.UNSUPPORTED: set(),
}


_LIVE_EVIDENCE = {
    EvidenceLevel.LIVE_PROVIDER_VERIFIED,
    EvidenceLevel.INDEPENDENT_CUSTOMER_VERIFIED,
    EvidenceLevel.STAGING_VERIFIED,
    EvidenceLevel.PRODUCTION_OBSERVED,
}


@dataclass(frozen=True)
class Capability:
    id: str
    category: str
    name: str
    state: SupportState
    evidence_level: EvidenceLevel | None
    evidence: str
    restriction: str | None
    protect_eligible: bool
    tags: tuple[str, ...] = field(default_factory=tuple)


_CAPABILITIES: tuple[Capability, ...] = (
    # --- Permission sources -------------------------------------------------
    Capability(
        "source.google_drive", "permission_source", "Google Drive",
        SupportState.PARTIAL, EvidenceLevel.CONTRACT_SIMULATED,
        "Drive adapter, shared-drive/group revocation pipeline and Guard policy tests pass locally with synthetic provider responses.",
        "No live tenant validation or live oracle was performed in this build. Constrained pilot requires per-tenant source evidence.",
        True, ("acl", "directory", "changes"),
    ),
    Capability(
        "source.microsoft365", "permission_source", "Microsoft 365 / SharePoint / OneDrive",
        SupportState.PARTIAL, EvidenceLevel.CONTRACT_SIMULATED,
        "Graph permission parsing, admin-consent and contract tests pass with synthetic responses.",
        "Protect is disabled until an independently verified effective-permission profile exists for the exact tenant, site and library. Shadow/preview only.",
        False, ("acl", "graph", "protect_restricted"),
    ),
    Capability(
        "source.permission_event_ingestion", "permission_source", "Provider permission event ingestion",
        SupportState.SUPPORTED, EvidenceLevel.LOCAL_INTEGRATION_VERIFIED,
        "Authenticated, tenant-scoped and idempotent event ingestion plus durable Guard event resolution are covered by local integration tests.",
        "A provider wake-up is not authoritative change state; the change feed must still be reconciled.",
        True, ("webhook", "reconciliation"),
    ),
    # --- Identity -----------------------------------------------------------
    Capability(
        "identity.oidc", "identity", "OIDC / SSO with stable subject mapping",
        SupportState.SUPPORTED, EvidenceLevel.LOCAL_INTEGRATION_VERIFIED,
        "JWT/JWKS verification, issuer/audience/tenant checks and explicit source-identity mapping are covered locally.",
        "A live customer IdP discovery/JWKS exchange was not executed in this build.",
        True, ("jwt", "jwks", "subject_mapping"),
    ),
    Capability(
        "identity.static_hs256", "identity", "Static HS256 development credentials",
        SupportState.PARTIAL, EvidenceLevel.UNIT_VERIFIED,
        "HS256 verification requires an explicitly configured issuer, audience and a key of at least 32 bytes.",
        "Development / managed integration only; not an enterprise SSO certification.",
        False, ("development_only",),
    ),
    # --- Routes -------------------------------------------------------------
    Capability(
        "route.buffered_http", "route", "Buffered HTTP request/response route",
        SupportState.SUPPORTED, EvidenceLevel.LOCAL_INTEGRATION_VERIFIED,
        "Reference Gateway enforces Layer 1 before model input and Layer 2 before the HTTP response body or first SSE byte.",
        "Certification is per deployed route; the static registry is not a customer route certificate.",
        True, ("gateway", "buffered"),
    ),
    Capability(
        "route.buffered_sse", "route", "Buffered SSE compatibility",
        SupportState.PARTIAL, EvidenceLevel.LOCAL_INTEGRATION_VERIFIED,
        "The Gateway generates non-streaming content, completes both Guard layers, then emits already-authorized SSE chunks.",
        "Not incremental model streaming. Native token streaming remains unsupported on protected routes.",
        True, ("gateway", "sse", "not_incremental"),
    ),
    Capability(
        "route.native_streaming", "route", "Native token streaming",
        SupportState.UNSUPPORTED, None,
        "No protected route emits model tokens before Layer 2 completes.",
        "Use buffered SSE compatibility or keep the route outside Protect.",
        False, ("streaming",),
    ),
    Capability(
        "route.websocket", "route", "WebSocket response routes",
        SupportState.UNSUPPORTED, None,
        "No WebSocket interception or certification path is implemented.",
        "A WebSocket route must remain outside the protected claim.",
        False, ("websocket",),
    ),
    Capability(
        "route.tools_agents", "route", "Tool / agent side-effect routes",
        SupportState.UNSUPPORTED, None,
        "Tool calls and agent actions are outside the RAG output-release boundary.",
        "Requires a separate action-authorization product; do not present it as covered.",
        False, ("tools", "agents"),
    ),
    Capability(
        "route.background_worker", "route", "Background worker results",
        SupportState.UNSUPPORTED, None,
        "No outbound worker result path is certified.",
        "A background result returned through a certified synchronous route must still carry provenance.",
        False, ("worker",),
    ),
    Capability(
        "route.cache_hit", "route", "Authorized cache-hit return path",
        SupportState.PARTIAL, EvidenceLevel.LOCAL_INTEGRATION_VERIFIED,
        "Signed dependency manifests, current principal checks, current authorization revision binding and Layer 2 re-check are covered locally.",
        "Redis integration is tested with an in-memory client; no live Redis/Memcached/SQL customer return path was certified in this build.",
        True, ("cache", "reauthorization"),
    ),
    # --- Retrieval ----------------------------------------------------------
    Capability(
        "retrieval.authorized_pgvector", "retrieval", "Authorization-first pgvector retrieval",
        SupportState.PARTIAL, EvidenceLevel.UNIT_VERIFIED,
        "Scope-predicate SQL, iterative scan settings, bounded overfetch, exact fallback and scope-violation rejection have SQL-shape/algorithm tests.",
        "The reference backend has not been executed against a live PostgreSQL/pgvector deployment. The Guard scope is bounded; very large tenants require a datastore-side ACL join.",
        True, ("pgvector", "ann", "exact_fallback"),
    ),
    Capability(
        "retrieval.scoped_backend_protocol", "retrieval", "Pluggable scoped vector backend",
        SupportState.SUPPORTED, EvidenceLevel.UNIT_VERIFIED,
        "Applications can supply a backend that accepts an explicit allowed-resource predicate and reports candidate counts.",
        "The application is responsible for applying the predicate in the datastore, not after global top-k.",
        True, ("protocol",),
    ),
    Capability(
        "retrieval.global_ann_post_filter", "retrieval", "Global ANN then ACL post-filter",
        SupportState.UNSUPPORTED, None,
        "Not offered: a global candidate window can starve entitled users or mis-rank authorized matches.",
        "Use the authorization-first retriever or an approved scoped adapter.",
        False, ("anti_pattern",),
    ),
    # --- Cache --------------------------------------------------------------
    Capability(
        "cache.none", "cache", "No application cache",
        SupportState.SUPPORTED, EvidenceLevel.LOCAL_INTEGRATION_VERIFIED,
        "Every protected answer is freshly generated and re-authorized at both Guard layers.",
        None, True, ("no_cache",),
    ),
    Capability(
        "cache.redis", "cache", "Redis signed dependency cache",
        SupportState.PARTIAL, EvidenceLevel.LOCAL_INTEGRATION_VERIFIED,
        "Reference Redis cache with signed manifests, revision binding and fail-closed stale/outage behavior is tested with an in-memory Redis client.",
        "No live customer Redis deployment or production return path was certified.",
        True, ("redis", "signed_manifest", "reauth"),
    ),
    Capability(
        "cache.memcached", "cache", "Memcached signed dependency cache",
        SupportState.PARTIAL, EvidenceLevel.UNIT_VERIFIED,
        "Backend adapter and signed-manifest verification are unit tested.",
        "No live Memcached deployment was executed.",
        True, ("memcached", "signed_manifest", "reauth"),
    ),
    Capability(
        "cache.sql", "cache", "SQL signed dependency cache",
        SupportState.PARTIAL, EvidenceLevel.UNIT_VERIFIED,
        "Backend adapter, expiry janitor and signed-manifest verification are unit tested.",
        "No live customer SQL cache deployment was executed.",
        True, ("sql", "signed_manifest", "reauth"),
    ),
    # --- Models -------------------------------------------------------------
    Capability(
        "model.openai_compatible", "model", "OpenAI-compatible buffered model transport",
        SupportState.PARTIAL, EvidenceLevel.LOCAL_INTEGRATION_VERIFIED,
        "Gateway transport, non-streaming generation and Layer 2 release are covered with a local model stub.",
        "No live model provider credential was spent; model-specific conformance is per deployment.",
        True, ("openai", "buffered"),
    ),
    Capability(
        "model.anthropic_native", "model", "Native Anthropic transport",
        SupportState.PARTIAL, EvidenceLevel.CONTRACT_SIMULATED,
        "Request/response contract tests only.",
        "Not live-provider validated in this build.",
        True, ("anthropic", "not_live_verified"),
    ),
    Capability(
        "model.gemini_native", "model", "Native Gemini transport",
        SupportState.PARTIAL, EvidenceLevel.CONTRACT_SIMULATED,
        "Request/response contract tests only.",
        "Not live-provider validated in this build.",
        True, ("gemini", "not_live_verified"),
    ),
    Capability(
        "model.direct_unmediated", "model", "Direct model call outside the Gateway",
        SupportState.UNSUPPORTED, None,
        "No enforcement is possible on a path that never reaches Guard.",
        "The compatibility scanner reports direct model clients as certification blockers.",
        False, ("bypass",),
    ),
    # --- Evidence -----------------------------------------------------------
    Capability(
        "evidence.signed_json", "evidence", "Signed JSON evidence reports",
        SupportState.SUPPORTED, EvidenceLevel.LOCAL_INTEGRATION_VERIFIED,
        "Ed25519-signed tenant-scoped reports with tamper, expiry and cross-tenant tests.",
        "Reports are control-plane observations, not independent certification of the customer deployment.",
        True, ("ed25519", "json"),
    ),
    Capability(
        "evidence.offline_verifier", "evidence", "Offline evidence verifier",
        SupportState.SUPPORTED, EvidenceLevel.LOCAL_INTEGRATION_VERIFIED,
        "Standalone verifier checks signature, schema, tenant/type/key expectations and expiry.",
        None, True, ("offline", "verifier"),
    ),
    Capability(
        "evidence.pdf_package", "evidence", "Signed PDF evidence package",
        SupportState.UNSUPPORTED, None,
        "Only signed JSON reports are implemented.",
        "Do not describe a PDF package as available.",
        False, ("pdf",),
    ),
    Capability(
        "evidence.authorization_revision_ledger", "evidence", "Signed authorization revision ledger",
        SupportState.SUPPORTED, EvidenceLevel.LOCAL_INTEGRATION_VERIFIED,
        "Monotonic revision allocation, chain linkage, signature verification and audit binding are covered locally.",
        "Content snapshot revision is observed as absent (NOT_OBSERVED) rather than fabricated.",
        True, ("revision", "ledger"),
    ),
    # --- Deployment ---------------------------------------------------------
    Capability(
        "deployment.docker_compose", "deployment", "Docker Compose deployment",
        SupportState.PARTIAL, EvidenceLevel.UNIT_VERIFIED,
        "Compose and Dockerfiles are validated statically by repository tests.",
        "Containers were not built or deployed in this constrained environment.",
        False, ("compose", "not_deployed"),
    ),
    Capability(
        "deployment.kubernetes", "deployment", "Kubernetes / Helm deployment",
        SupportState.UNSUPPORTED, None,
        "No chart or operator is shipped.",
        None, False, ("kubernetes",),
    ),
    # --- Release profiles ---------------------------------------------------
    Capability(
        "release.independent_certification", "release", "Independent customer / provider certification",
        SupportState.UNSUPPORTED, None,
        "No independent customer RAG, live provider tenant or security assessment was completed in this build.",
        "A CERTIFIED_PROFILE or broad-production claim is therefore unavailable.",
        False, ("go_no_go",),
    ),
)


def _adapter_capability(entry: dict[str, Any]) -> Capability:
    certification = str(entry.get("certification", ""))
    if certification == "REFERENCE_IMPLEMENTATION_TESTED":
        state, evidence = SupportState.PARTIAL, EvidenceLevel.LOCAL_INTEGRATION_VERIFIED
    elif certification == "IMPLEMENTED_AND_TESTED":
        state, evidence = SupportState.SUPPORTED, EvidenceLevel.UNIT_VERIFIED
    elif certification == "IMPLEMENTED_NOT_FRAMEWORK_CERTIFIED":
        state, evidence = SupportState.PARTIAL, EvidenceLevel.CONTRACT_SIMULATED
    else:
        state, evidence = SupportState.PARTIAL, EvidenceLevel.CONTRACT_SIMULATED
    return Capability(
        id=f"adapter.{entry['id']}", category="integration_adapter",
        name=str(entry["name"]), state=state, evidence_level=evidence,
        evidence=f"Adapter registry certification: {certification}. {entry.get('validation_requirements', '')}",
        restriction=str(entry.get("limitation") or "") or None,
        protect_eligible=bool(entry.get("protect_mode")),
        tags=("adapter", str(entry.get("framework", "")).lower().replace(" ", "_")),
    )


def capabilities() -> tuple[Capability, ...]:
    return _CAPABILITIES + tuple(_adapter_capability(entry) for entry in adapter_registry())


def validate(capabilities_: Iterable[Capability] = _CAPABILITIES) -> None:
    seen: set[str] = set()
    for item in capabilities_:
        if not item.id or item.id in seen:
            raise ValueError("DUPLICATE_CAPABILITY_ID")
        seen.add(item.id)
        if item.state in _MINIMUM_EVIDENCE and item.evidence_level is not None:
            if item.evidence_level not in _MINIMUM_EVIDENCE[item.state]:
                raise ValueError("EVIDENCE_STATE_MISMATCH")
        if item.state in {SupportState.SUPPORTED, SupportState.PARTIAL} and item.evidence_level is None:
            raise ValueError("EVIDENCE_REQUIRED")
        if item.state == SupportState.UNSUPPORTED and item.evidence_level is not None:
            raise ValueError("UNSUPPORTED_CAPABILITY_HAS_EVIDENCE")
        if item.protect_eligible and item.state == SupportState.UNSUPPORTED:
            raise ValueError("UNSUPPORTED_CAPABILITY_CANNOT_BE_PROTECT_ELIGIBLE")
        if item.evidence_level in _LIVE_EVIDENCE and "live" not in item.tags:
            raise ValueError("LIVE_EVIDENCE_REQUIRES_LIVE_SCOPE")
        if not item.evidence.strip():
            raise ValueError("EVIDENCE_TEXT_REQUIRED")


def release_gate() -> dict[str, Any]:
    """Static release vocabulary. A pilot still needs per-tenant evidence."""
    live = {
        item.id for item in capabilities()
        if item.evidence_level in {
            EvidenceLevel.LIVE_PROVIDER_VERIFIED,
            EvidenceLevel.INDEPENDENT_CUSTOMER_VERIFIED,
            EvidenceLevel.STAGING_VERIFIED,
            EvidenceLevel.PRODUCTION_OBSERVED,
        }
    }
    blockers = [
        "No live Google Drive tenant validation or independent allow/deny identities.",
        "No certified Microsoft effective-permission profile; Microsoft Protect remains restricted.",
        "No production route certificate for every active customer response path.",
        "No live PostgreSQL/pgvector execution evidence for the reference retrieval backend.",
        "No live Redis/cache return-path certification and no live model-provider conformance.",
        "No tested production rollback, backup restore exercise on the customer deployment, HA/load or independent security assessment.",
    ]
    return {
        "schema": RELEASE_GATE_SCHEMA,
        "profiles": {
            "LAB": {
                "eligible": True,
                "reason": "Local deterministic tests and synthetic provider contracts only.",
            },
            "CONSTRAINED_PILOT": {
                "eligible": False,
                "reason": "Requires per-tenant source, route, retrieval, cache, model and rollback evidence. Static repository evidence cannot satisfy it.",
            },
            "CERTIFIED_PROFILE": {
                "eligible": False,
                "reason": "Requires independently observed live evidence for the exact configuration.",
            },
            "NO_GO": {
                "eligible": True,
                "reason": "Broad production remains NO_GO until every blocker below is closed for the exact deployment.",
            },
        },
        "live_evidence_capabilities": sorted(live),
        "blockers": blockers,
        "note": "Profile eligibility is evaluated per deployment. This response is product-wide registry truth, not a tenant certificate.",
    }


def snapshot() -> dict[str, Any]:
    validate(capabilities())
    return {
        "schema": CAPABILITY_REGISTRY_SCHEMA,
        "evidence_levels": [level.value for level in EvidenceLevel],
        "support_states": [state.value for state in SupportState],
        "capabilities": [
            {
                **asdict(item),
                "state": item.state.value,
                "evidence_level": item.evidence_level.value if item.evidence_level else None,
            }
            for item in capabilities()
        ],
        "release_gate": release_gate(),
        "limitations": [
            "A static registry entry is not a customer deployment certificate.",
            "Mocked or synthetic provider responses never promote a capability to LIVE_PROVIDER_VERIFIED.",
            "Unlisted routes, providers, caches and model paths are UNKNOWN and must be treated as unsupported by the compatibility scanner.",
        ],
    }


_CSV_FIELDS = (
    "id", "category", "name", "state", "evidence_level", "protect_eligible",
    "restriction", "evidence", "tags",
)


def csv_text() -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_CSV_FIELDS)
    writer.writeheader()
    for item in capabilities():
        row = asdict(item)
        row["state"] = item.state.value
        row["evidence_level"] = item.evidence_level.value if item.evidence_level else ""
        row["tags"] = ";".join(item.tags)
        row["protect_eligible"] = "true" if item.protect_eligible else "false"
        writer.writerow({key: row[key] for key in _CSV_FIELDS})
    return buffer.getvalue()


__all__ = [
    "CAPABILITY_REGISTRY_SCHEMA",
    "EvidenceLevel",
    "RELEASE_GATE_SCHEMA",
    "SupportState",
    "capabilities",
    "csv_text",
    "release_gate",
    "snapshot",
    "validate",
]
