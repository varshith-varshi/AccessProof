from __future__ import annotations

import json
import logging
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
