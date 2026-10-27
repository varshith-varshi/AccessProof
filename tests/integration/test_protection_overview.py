from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    AIApplication,
    Base,
    SessionLocal,
    SourceConnection,
    engine,
)
from apps.api.accessproof_api.protection_state import PROTECTION_STATES


def _signup(client, email: str, organization_name: str):
    response = client.post("/api/v1/auth/signup", json={
        "email": email,
        "password": "correct horse battery staple",
        "organization_name": organization_name,
    })
    assert response.status_code == 201, response.text
    return response.json()


def _headers(account):
    return {
        "Authorization": f"Bearer {account['session_token']}",
        "X-Organization-ID": account["organization_id"],
    }


def _reset_schema():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)


def _create_guard(client, headers, name="Laptop Guard"):
    response = client.post("/api/v1/guards", headers=headers, json={"name": name})
    assert response.status_code == 201, response.text
    return response.json()


def _create_source(client, headers, name="Finance Drive"):
    response = client.post("/api/v1/current/sources", headers=headers, json={
        "provider": "generic",
        "name": name,
        "boundary": "finance/",
    })
    assert response.status_code == 201, response.text
    return response.json()


def _create_application(client, headers, application_id, **extra):
    response = client.post("/api/v1/current/ai-applications", headers=headers, json={
        "application_id": application_id,
        "name": application_id,
        **extra,
    })
    assert response.status_code == 201, response.text
    return response.json()


def _overview(client, headers):
    response = client.get("/api/v1/current/protection/overview", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def _application(overview, application_id):
    return next(
        application for application in overview["applications"]
        if application["application_id"] == application_id
    )


def test_overview_is_empty_and_explicit_for_a_new_tenant():
    _reset_schema()
    with TestClient(app) as client:
        account = _signup(client, "empty-overview@example.com", "Empty overview org")
        overview = _overview(client, _headers(account))

        assert overview["applications"] == []
        assert set(overview["state_counts"]) == set(PROTECTION_STATES)
        assert all(count == 0 for count in overview["state_counts"].values())
        assert overview["totals"] == {
            "applications_registered": 0,
            "applications_protected_verified": 0,
            "applications_not_verified": 0,
            "applications_unsupported": 0,
            "guards_total": 0,
            "guards_online": 0,
            "guards": {"online": 0, "offline": 0, "not_enrolled": 0, "revoked": 0},
            "sources_total": 0,
            "sources_fresh": 0,
            "sources_stale": 0,
        }


def test_unbound_and_unsupported_applications_are_never_protected():
    _reset_schema()
    with TestClient(app) as client:
        account = _signup(client, "overview-states@example.com", "Overview states org")
        headers = _headers(account)
        _create_application(client, headers, "unbound-rag")
        # Legacy app records are kept read-only for audit after V1 retires
        # SDK and generic HTTP integrations; new POST registrations reject them.
        with SessionLocal() as db:
            db.add(AIApplication(
                organization_id=account["organization_id"],
                application_id="http-rag", name="Historical HTTP target",
                adapter_type="generic-http", adapter_contract_version="target-config/v1",
            ))
            db.commit()

        overview = _overview(client, headers)

        unbound = _application(overview, "unbound-rag")
        assert unbound["effective_state"] == "NOT_CONFIGURED"
        assert unbound["guard"]["id"] is None
        assert unbound["source"]["id"] is None
        assert unbound["decision_telemetry"]["telemetry"] == "NO_DATA"
        assert unbound["decision_telemetry"]["layer1"] is None
        assert unbound["latest_decision_at"] is None
        assert unbound["failed_checks"]

        unsupported = _application(overview, "http-rag")
        assert unsupported["effective_state"] == "UNSUPPORTED"
        assert unsupported["adapter"]["protect_capable"] is False
        assert unsupported["decision_telemetry"]["telemetry"] == "NO_DATA"

        assert overview["totals"]["applications_registered"] == 2
        assert overview["totals"]["applications_protected_verified"] == 0
        assert overview["totals"]["applications_not_verified"] == 2
        assert overview["totals"]["applications_unsupported"] == 1
        assert overview["state_counts"]["NOT_CONFIGURED"] == 1
        assert overview["state_counts"]["UNSUPPORTED"] == 1


def test_bound_but_unconnected_source_is_blocked_not_verified():
    _reset_schema()
    with TestClient(app) as client:
        account = _signup(client, "overview-blocked@example.com", "Blocked org")
        headers = _headers(account)
        guard = _create_guard(client, headers)
        source = _create_source(client, headers)
        _create_application(
            client, headers, "blocked-rag",
            guard_id=guard["id"], source_id=source["id"],
        )

        overview = _overview(client, headers)
        blocked = _application(overview, "blocked-rag")
        assert blocked["effective_state"] == "BLOCKED"
        assert blocked["source"]["status"] == "not_configured"
        assert blocked["guard"]["health"] == "not_enrolled"
        assert overview["totals"]["applications_protected_verified"] == 0
        assert overview["totals"]["guards"]["not_enrolled"] == 1


def test_shadow_and_legacy_protect_are_never_reported_as_verified():
    _reset_schema()
    with TestClient(app) as client:
        account = _signup(client, "overview-incomplete@example.com", "Incomplete org")
        headers = _headers(account)
        guard = _create_guard(client, headers)
        source = _create_source(client, headers)
        _create_application(
            client, headers, "shadow-rag",
            guard_id=guard["id"], source_id=source["id"],
        )
        _create_application(
            client, headers, "protect-rag",
            guard_id=guard["id"], source_id=source["id"],
        )
        mode = client.patch(
            "/api/v1/current/ai-applications/protect-rag/mode",
            headers=headers, json={"mode": "protect"},
        )
        assert mode.status_code == 409

        # Simulate a legacy row that claims protect without the new machine
        # certification; the overview must not echo that claim as verified.
        with SessionLocal() as db:
            row = db.scalar(select(AIApplication).where(
                AIApplication.organization_id == account["organization_id"],
                AIApplication.application_id == "protect-rag",
            ))
            row.mode = "protect"
            source_row = db.get(SourceConnection, source["id"])
            source_row.status = "connected"
            source_row.last_validated_at = datetime.now(timezone.utc)
            db.commit()

        overview = _overview(client, headers)
        shadow = _application(overview, "shadow-rag")
        assert shadow["mode"] == "shadow"
        assert shadow["effective_state"] != "PROTECTED_VERIFIED"

        protect = _application(overview, "protect-rag")
        assert protect["mode"] == "protect"
        assert protect["effective_state"] in {
            "VALIDATING", "DEGRADED", "STALE", "CERTIFICATION_EXPIRED",
        }
        assert protect["effective_state"] != "PROTECTED_VERIFIED"
        assert protect["reason_code"]

        assert overview["totals"]["applications_protected_verified"] == 0
        assert overview["totals"]["guards_total"] == 1
        assert overview["totals"]["guards"]["not_enrolled"] == 1
        assert overview["totals"]["sources_total"] == 1
        assert overview["totals"]["sources_fresh"] == 0


def test_overview_is_tenant_scoped():
    _reset_schema()
    with TestClient(app) as client:
        first = _signup(client, "tenant-one@example.com", "Tenant one")
        second = _signup(client, "tenant-two@example.com", "Tenant two")
        _create_application(client, _headers(first), "first-tenant-rag")

        second_overview = _overview(client, _headers(second))
        assert second_overview["applications"] == []
        assert second_overview["totals"]["applications_registered"] == 0

        first_overview = _overview(client, _headers(first))
        assert [row["application_id"] for row in first_overview["applications"]] == [
            "first-tenant-rag"
        ]
