"""Post-install Gateway preflight is automatic, read-only and fail-closed."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from apps.api.accessproof_api import app as api
from apps.api.accessproof_api import gateway_pairing


def _app() -> SimpleNamespace:
    return SimpleNamespace(
        id="app-row", organization_id="tenant-a",
        application_id="synthetic-rag", adapter_type="accessproof-gateway",
        source_id="source-a", guard_id="guard-a",
    )


def _checklist() -> list[dict]:
    return [
        {"code": "GUARD_POLICY_INSTALLED", "ok": True, "reason": None},
        {
            "code": "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED",
            "ok": False,
            "reason": "Live SharePoint evidence is missing.",
        },
        {
            "code": "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED",
            "ok": False,
            "reason": "Guard challenge evidence missing.",
        },
    ]


def test_automatic_verification_never_certifies_or_enables_protect(monkeypatch):
    monkeypatch.setattr(api, "_automatic_activation_checklist", lambda db, row: _checklist())
    row = _app()
    previous_mode = getattr(row, "mode", None)
    result = api._automatic_gateway_pairing_verification(object(), row)
    assert result["state"] == "action_required"
    assert result["checks_passed"] == 1
    assert result["checks_total"] == 3
    assert result["failed_check_codes"] == [
        "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED",
        "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED",
    ]
    assert result["production_certification"] is False
    assert result["protect_activated"] is False
    assert getattr(row, "mode", None) == previous_mode


def test_server_checklist_failure_fails_closed(monkeypatch):
    def fail(db, row):
        raise RuntimeError("Synthetic DB unavailable")
    monkeypatch.setattr(api, "_automatic_activation_checklist", fail)
    result = api._automatic_gateway_pairing_verification(object(), _app())
    assert result["state"] == "verification_unavailable"
    assert result["failed_check_codes"] == ["AUTOMATIC_READINESS_CHECK_UNAVAILABLE"]
    assert result["protect_activated"] is False


@pytest.mark.parametrize("checks", [[], [{"code": "BROKEN", "ok": 1}], [{"ok": True}]])
def test_invalid_server_checklist_fails_closed(monkeypatch, checks):
    monkeypatch.setattr(api, "_automatic_activation_checklist", lambda db, row: checks)
    assert api._automatic_gateway_pairing_verification(object(), _app())["state"] == "verification_unavailable"


def test_green_snapshot_does_not_activate_protect(monkeypatch):
    monkeypatch.setattr(
        api, "_automatic_activation_checklist",
        lambda db, row: [{"code": "SYNTHETIC_ONLY", "ok": True}],
    )
    result = api._automatic_gateway_pairing_verification(object(), _app())
    assert result["state"] == "checks_passed_requires_independent_review"
    assert not result["production_certification"]
    assert not result["protect_activated"]


def test_claim_runs_verification_only_after_valid_tenant_and_guard(monkeypatch):
    row = _app()
    guard = SimpleNamespace(
        organization_id="tenant-a", enrolled_at="yes", revoked_at=None
    )
    class Session:
        def get(self, model, id):
            return {"app-row": row, "guard-a": guard}.get(id)
    class Spy:
        calls = 0
        def receive(self, *, token, installation, application_is_valid):
            self.calls += 1
            assert application_is_valid("tenant-a", "app-row", "synthetic-rag")
            assert not application_is_valid("attacker-tenant", "app-row", "synthetic-rag")
            return {"state": "installation_reported_unverified"}
    spy = Spy()
    monkeypatch.setattr(gateway_pairing, "receive", spy.receive)
    monkeypatch.setattr(api, "_automatic_activation_checklist", lambda db, row: _checklist())
    monkeypatch.setattr(api, "set_tenant_context", lambda db, org: None)
    monkeypatch.setattr(api.verification_engine, "start_or_resume", lambda db, row, **kwargs: SimpleNamespace(id="durable-run"))
    # D-02 issuance is exercised against a real DB in test_gateway_presence.py.
    issued = []
    monkeypatch.setattr(api.gateway_presence, "issue_installation", lambda db, row, **kwargs: (
        issued.append(kwargs) or (SimpleNamespace(id="installation-1"), "machine-credential-once")))
    monkeypatch.setattr(api, "_audit", lambda *args, **kwargs: None)
    Session.commit = lambda self: None
    response = api.claim_customer_gateway_pairing(
        installation={"deployment_sha256": "a" * 64, "route_sha256": "b" * 64},
        authorization="Bearer synthetic-private-test",
        db=Session(),
    )
    assert spy.calls == 1
    assert response["verification"]["state"] == "action_required"
    assert response["verification_run_id"] == "durable-run"
    assert not response["verification"]["production_certification"]
    assert issued == [{"deployment_sha256": "a" * 64, "route_sha256": "b" * 64}]
    assert response["gateway_presence"]["installation_id"] == "installation-1"
    assert response["gateway_presence"]["credential"] == "machine-credential-once"


def test_claim_missing_pairing_token_requires_machine_auth():
    with pytest.raises(HTTPException) as error:
        api.claim_customer_gateway_pairing(installation={}, authorization=None, db=object())
    assert error.value.status_code == 401
