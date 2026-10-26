from __future__ import annotations

from apps.api.accessproof_api.config import Settings
from scripts import validate_production_config as command


def test_production_config_validator_reports_names_not_secret_values(monkeypatch, capsys) -> None:
    secret = "do-not-print-this-production-secret-value"
    monkeypatch.setattr(command, "settings", Settings(env="production", session_hmac_key=secret))
    assert command.main() == 1
    output = capsys.readouterr().out
    assert "FAIL" in output
    assert secret not in output
