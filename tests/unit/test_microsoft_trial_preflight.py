"""Offline contract tests for the explicitly read-only Microsoft trial preflight."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from scripts import validate_microsoft_trial_preflight as check


def valid_config() -> check.MicrosoftTrialConfig:
    return check.MicrosoftTrialConfig(
        tenant_id="11111111-1111-4111-8111-111111111111",
        site_id=(
            "example.sharepoint.com,"
            "22222222-2222-4222-8222-222222222222,"
            "33333333-3333-4333-8333-333333333333"
        ),
        list_id="44444444-4444-4444-8444-444444444444",
        drive_id="drive-id",
        root_id="Folder_root-123",
        client_id="synthetic-app-id",
        client_secret="SECRET_MUST_NEVER_PRINT",
    )


def test_preflight_requires_exact_valid_source_boundary():
    conf = valid_config()
    assert check.config_issues(conf) == []
    assert "invalid:root_id" in check.config_issues(
        check.MicrosoftTrialConfig(**{**vars(conf), "root_id": "../outside"})
    )
    assert "invalid:root_id" not in check.config_issues(
        check.MicrosoftTrialConfig(**{**vars(conf), "root_id": "folder-root_123"})
    )
    assert "invalid:tenant_site_or_list_id" in check.config_issues(
        check.MicrosoftTrialConfig(**{**vars(conf), "site_id": "example.com,bad,bad"})
    )


def test_license_error_is_classified_without_provider_body_or_token():
    req = httpx.Request("GET", "https://graph.microsoft.com/v1.0/sites/root")
    resp = httpx.Response(
        400, json={"error": {"message": "Tenant does not have a SPO license."}},
        request=req,
    )
    exc = httpx.HTTPStatusError("Sensitive token SECRET_MUST_NEVER_PRINT",
                                request=req, response=resp)
    status = check.provider_error(exc)
    assert status == "BLOCKED_SHAREPOINT_LICENSE_OR_PROVISIONING"
    assert "SECRET" not in status


@pytest.mark.asyncio
async def test_read_only_preflight_checks_exact_boundary_without_exposing_token(monkeypatch):
    conf = valid_config()
    calls: list[tuple] = []

    def token_factory(**kwargs):
        calls.append(("token", kwargs["tenant_id"], kwargs["client_id"]))
        return "SECRET_GRAPH_BEARER", datetime.now(timezone.utc) + timedelta(minutes=45)

    class FakeAdapter:
        def __init__(self, **kwargs):
            calls.append(("adapter", kwargs["test_root_item_id"], kwargs["sharepoint_site_id"]))
            assert kwargs["access_token"] == "SECRET_GRAPH_BEARER"
            self._client = self

        async def validate_connection(self):
            calls.append(("validate_connection",))

        async def list_boundary_resources(self, *, max_resources):
            calls.append(("list_metadata", max_resources))
            return [{"file": {}}, {"folder": {}}]

        async def aclose(self):
            calls.append(("close",))

    monkeypatch.setattr(check, "graph_app_token", token_factory)
    monkeypatch.setattr(check, "Microsoft365Adapter", FakeAdapter)
    result = await check.validate(conf)
    assert result["result"] == "CONNECTED_READ_ONLY"
    assert result["file_metadata_count"] == 1
    assert result["sharepoint_protect"] == "NOT_CERTIFIED"
    assert result["permission_revocation"] == "NOT_TESTED"
    assert calls[0][0] == "token"
    assert calls[-1] == ("close",)
    assert "SECRET" not in str(result)


def test_no_live_flag_does_not_call_graph_even_if_configured(monkeypatch, capsys):
    monkeypatch.setattr(check.MicrosoftTrialConfig, "from_environment", valid_config)
    monkeypatch.setattr(check, "validate", lambda _: pytest.fail("network must not be called"))
    monkeypatch.setattr("sys.argv", ["validator"])
    assert check.main() == 0
    out = capsys.readouterr().out
    assert "READY_FOR_LIVE_PREFLIGHT" in out
    assert "SECRET_MUST_NEVER_PRINT" not in out
