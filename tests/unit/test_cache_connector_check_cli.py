from __future__ import annotations

from packages.demo_cache import check


def test_cache_health_check_reports_no_config_without_secrets(monkeypatch, capsys):
    monkeypatch.setattr(check, "configured_cache_backend", lambda: None)
    assert check.main() == 2
    assert capsys.readouterr().out.strip() == "CACHE_CONNECTOR_NOT_CONFIGURED"


def test_cache_health_check_reports_verified_ready(monkeypatch, capsys):
    class Ready:
        def ping(self):
            return True
    monkeypatch.setattr(check, "configured_cache_backend", lambda: Ready())
    assert check.main() == 0
    assert capsys.readouterr().out.strip() == "CACHE_CONNECTOR_READY"


def test_cache_health_check_does_not_leak_upstream_error_or_password(monkeypatch, capsys):
    class Broken:
        def ping(self):
            raise RuntimeError("postgresql://account:SECRET@customer-private-database")
    monkeypatch.setattr(check, "configured_cache_backend", lambda: Broken())
    assert check.main() == 1
    result = capsys.readouterr().out
    assert result.strip() == "CACHE_CONNECTOR_NOT_READY"
    assert "SECRET" not in result
