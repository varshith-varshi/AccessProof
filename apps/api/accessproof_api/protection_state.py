"""Explicit, backend-owned protection state model.

The UI must never infer "Protected" from a mode flag or from the absence of
errors.  This module maps the server-computed readiness checks onto one
documented state, including states that are explicitly *not* verified.
"""

from __future__ import annotations

from typing import Any

PROTECTION_STATES: tuple[str, ...] = (
    "NOT_CONFIGURED",
    "CONNECTED",
    "VALIDATING",
    "SHADOW",
    "PROTECT_PENDING",
    "PROTECTED_VERIFIED",
    "PROTECTED_MANUAL_VALIDATION_PENDING",
    "DEGRADED",
    "STALE",
    "BLOCKED",
    "CERTIFICATION_EXPIRED",
    "UNSUPPORTED",
    "UNKNOWN",
)

# Freshness failures can be repaired by waiting for/renewing synchronization.
STALE_CHECK_CODES = frozenset({
    "GUARD_HEARTBEAT_RECENT",
    "PERMISSION_SOURCE_SYNCED",
    "PERMISSION_DIRECTORY_SYNCED",
    "PERMISSION_SOURCE_USABLE",
})

# These checks require a fresh machine-bound route challenge, not configuration.
CERTIFICATION_CHECK_CODES = frozenset({
    "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED",
    "CUSTOMER_RAG_CUTOVER_NOT_VERIFIED",
    "LAYER1_INTEGRATION_CONFIRMED",
    "LAYER2_INTEGRATION_CONFIRMED",
    "PROVENANCE_READY",
    "BUFFERED_RESPONSE_GATE_READY",
})

STATE_MESSAGES: dict[str, str] = {
    "NOT_CONFIGURED": "A Guard and an authoritative permission source must both be bound before protection can be evaluated.",
    "CONNECTED": "The Guard and source are connected, but required configuration or policy synchronization is incomplete.",
    "VALIDATING": "Protection activation is in progress; the Guard has not acknowledged a verified Protect state.",
    "SHADOW": "The application is observing authorization decisions in Shadow mode. No response has been certified as protected.",
    "PROTECT_PENDING": "The customer-side Guard has not yet acknowledged the requested Protect mode.",
    "PROTECTED_VERIFIED": "Live source/Guard/Gateway checks and optional route certification passed. Protection is active and can degrade if enforcement evidence becomes stale.",
    "PROTECTED_MANUAL_VALIDATION_PENDING": "Protect is active with source authorization and Guard/Gateway enforcement ready. Customer-specific allow/deny/tamper/revocation challenges have not been independently certified; manual validation is recommended.",
    "DEGRADED": "Protection is requested but one or more required security checks fail. Unsafe responses must remain blocked.",
    "STALE": "Previously configured protection cannot be verified because Guard or source evidence is stale. Treat requests as unverified.",
    "BLOCKED": "The bound Guard or permission source is revoked or disconnected. Requests must fail closed.",
    "CERTIFICATION_EXPIRED": "The application was previously certified, but its route/Guard certification has expired and requires re-verification.",
    "UNSUPPORTED": "The selected adapter does not provide a verified Layer 1 and Layer 2 Protect boundary for this route.",
    "UNKNOWN": "The control plane cannot currently determine a verified state. Treat the application as unprotected.",
}


def classify_protection_state(
    checks: list[dict[str, Any]],
    mode: str,
    *,
    adapter_protect_capable: bool,
    has_guard: bool,
    has_source: bool,
    guard_revoked: bool,
    source_disconnected: bool,
    certification_expired: bool,
    route_certified: bool = True,
) -> str:
    """Return one explicit state; never promote an unverified app to PROTECTED_VERIFIED."""
    failed = {str(check.get("code")) for check in checks if not check.get("ok")}

    if not adapter_protect_capable:
        return "UNSUPPORTED"
    if not has_guard or not has_source:
        return "NOT_CONFIGURED"
    if guard_revoked or source_disconnected:
        return "BLOCKED"
    if mode not in {"shadow", "protect", "protect_pending"}:
        return "UNKNOWN"

    if mode == "protect":
        if not failed:
            return "PROTECTED_VERIFIED" if route_certified else "PROTECTED_MANUAL_VALIDATION_PENDING"
        if failed <= STALE_CHECK_CODES:
            return "STALE"
        if failed <= CERTIFICATION_CHECK_CODES:
            return "CERTIFICATION_EXPIRED" if certification_expired else "VALIDATING"
        return "DEGRADED"
    if mode == "protect_pending":
        return "PROTECT_PENDING"
    if mode == "shadow":
        return classify_shadow(failed)
    return "UNKNOWN"


def classify_shadow(failed: set[str]) -> str:
    """Shadow mode ignores verification checks; those are only claimed in Protect."""
    configuration_failures = failed - CERTIFICATION_CHECK_CODES
    if not configuration_failures:
        return "SHADOW"
    if configuration_failures <= STALE_CHECK_CODES:
        return "STALE"
    return "CONNECTED"
