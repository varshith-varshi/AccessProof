from packages.observability.tracing import configure_tracing


def test_tracing_is_zero_config_noop(monkeypatch):
    monkeypatch.delenv("ACCESSPROOF_OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
    assert configure_tracing("accessproof-test") is False
