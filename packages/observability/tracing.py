from __future__ import annotations

import os
import threading

from opentelemetry import trace

_lock = threading.Lock()
_configured = False


def configure_tracing(default_service_name: str) -> bool:
    """Configure OTLP tracing when an exporter endpoint is explicitly supplied.

    The OpenTelemetry SDK/exporter is an optional production dependency. Local
    development remains a zero-config no-op while instrumentation in the test
    engine continues to use the API-level no-op provider safely.
    """
    global _configured
    endpoint = os.getenv("ACCESSPROOF_OTEL_EXPORTER_OTLP_ENDPOINT") or os.getenv(
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
    )
    if not endpoint:
        return False
    if _configured:
        return True
    with _lock:
        if _configured:
            return True
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
        except ImportError as exc:  # pragma: no cover - depends on production extra
            raise RuntimeError(
                "OTLP tracing endpoint is configured but the AccessProof observability extra is not installed"
            ) from exc
        service_name = (
            os.getenv("OTEL_SERVICE_NAME")
            or os.getenv("ACCESSPROOF_OTEL_SERVICE_NAME")
            or default_service_name
        )
        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(provider)
        _configured = True
        return True
