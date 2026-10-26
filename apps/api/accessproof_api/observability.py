from __future__ import annotations

import json
import logging
import re
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

api_requests = Counter(
    "accessproof_api_requests_total", "API requests", ["method", "route", "status"]
)
api_latency = Histogram(
    "accessproof_api_request_duration_seconds", "API request latency", ["method", "route"]
)
active_requests = Gauge("accessproof_api_active_requests", "Active API requests")

run_outcomes = Counter(
    "accessproof_run_outcomes_total", "Permission regression outcomes", ["outcome", "provider"]
)
propagation_latency = Histogram(
    "accessproof_stable_propagation_seconds",
    "Stable source-to-AI denial propagation latency",
    ["provider"],
)
exposure_window = Histogram(
    "accessproof_exposure_window_seconds",
    "Observed forbidden-exposure window after source denial",
    ["provider"],
)
runner_leases = Counter("accessproof_runner_leases_total", "Runner lease requests", ["result"])
runner_heartbeats = Counter("accessproof_runner_heartbeats_total", "Accepted runner heartbeats")
cleanup_attempts = Counter(
    "accessproof_cleanup_attempts_total", "Cleanup task attempts", ["result", "provider"]
)
webhook_attempts = Counter(
    "accessproof_webhook_delivery_attempts_total",
    "Webhook delivery processing outcomes",
    ["result"],
)
email_attempts = Counter(
    "accessproof_email_delivery_attempts_total", "Email delivery processing outcomes", ["result"]
)
operational_alerts = Counter(
    "accessproof_operational_alerts_total", "Operational alerts created", ["kind", "severity"]
)

# Database-backed gauges are refreshed immediately before the API /metrics scrape.
# They deliberately avoid tenant/project/runner IDs as labels to prevent cardinality
# explosions or accidental customer metadata exposure in the metrics stream.
run_queue_depth = Gauge(
    "accessproof_run_queue_depth", "Non-terminal runs waiting for or held by runners", ["state"]
)
runner_health = Gauge("accessproof_runner_health_count", "Runner count by health state", ["health"])
runner_heartbeat_max_age = Gauge(
    "accessproof_runner_heartbeat_max_age_seconds", "Oldest non-revoked runner heartbeat age"
)
cleanup_queue_depth = Gauge(
    "accessproof_cleanup_queue_depth", "Cleanup task count by status", ["status"]
)
webhook_queue_depth = Gauge(
    "accessproof_webhook_queue_depth", "Webhook delivery count by status", ["status"]
)
email_queue_depth = Gauge(
    "accessproof_email_queue_depth", "Transactional email count by status", ["status"]
)
source_connection_health = Gauge(
    "accessproof_source_connection_count", "Source connection count by status", ["status"]
)

# Authorization/evidence metrics. Labels are restricted to bounded decision
# reasons and provider names; employee, resource and application identifiers
# never become metric labels.
authz_decisions = Counter(
    "accessproof_authz_decision_total",
    "Guard authorization decisions accepted from machine-authenticated audit",
    ["layer", "result", "reason"],
)
authz_decision_latency = Histogram(
    "accessproof_authz_decision_latency_seconds",
    "Guard authorization decision latency where the Guard reports it",
)
guard_revision_lag = Gauge(
    "accessproof_guard_revision_lag_seconds",
    "Largest pending interval between control-plane authorization revision creation and Guard acknowledgement",
)
source_freshness = Gauge(
    "accessproof_source_freshness_seconds", "Age of the last trusted ACL synchronization", ["provider"]
)
directory_freshness = Gauge(
    "accessproof_directory_freshness_seconds", "Age of the last trusted directory synchronization", ["provider"]
)
provider_event_lag = Gauge(
    "accessproof_provider_event_lag_seconds",
    "Largest observed delay between provider change observation and receipt",
    ["provider"],
)
revocation_end_to_end = Histogram(
    "accessproof_revocation_end_to_end_seconds",
    "Observed provider change to first Guard denial, measured from retained events",
)
route_certificate_age = Gauge(
    "accessproof_route_certificate_age_seconds",
    "Age of the oldest current reference-route certificate reported by AccessProof",
)
protected_route_coverage = Gauge(
    "accessproof_protected_route_coverage_ratio",
    "Known Protect-bound applications with a current route certificate divided by known Protect-bound applications",
)
cache_reauth = Counter(
    "accessproof_cache_reauth_total", "Protected cache-hit reauthorization outcomes", ["result"]
)
layer2_blocks = Counter(
    "accessproof_layer2_block_total", "Layer 2 blocked releases", ["reason"]
)
provider_api_errors = Counter(
    "accessproof_provider_api_error_total", "Provider API errors by provider and status", ["provider", "status"]
)
jit_verifications = Counter(
    "accessproof_jit_verification_total", "Optional just-in-time provider verifications", ["result"]
)
evidence_generation = Counter(
    "accessproof_evidence_generation_total", "Evidence report generation outcomes", ["result"]
)
scanner_bypass_findings = Counter(
    "accessproof_scanner_bypass_finding_total", "Read-only compatibility scanner bypass findings", ["type"]
)

_SAFE_LABEL = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def bounded_reason(reason: str) -> str:
    """Keep metric cardinality bounded even if an upstream reason is malformed."""
    return reason if _SAFE_LABEL.fullmatch(reason) else "UNCLASSIFIED"

logger = logging.getLogger("accessproof")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


def log_request(
    *, correlation_id: str, method: str, path: str, status: int, duration_seconds: float
) -> None:
    logger.info(
        json.dumps(
            {
                "event": "http_request",
                "correlation_id": correlation_id,
                "method": method,
                "path": path,
                "status": status,
                "duration_ms": round(duration_seconds * 1000, 2),
            },
            separators=(",", ":"),
        )
    )


def metrics_payload() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
