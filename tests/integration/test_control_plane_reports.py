import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, ControlPlaneReport, SessionLocal, engine


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


def _create_report(client, headers, report_type="APPLICATION_COVERAGE"):
    response = client.post(
        "/api/v1/current/reports", headers=headers, json={"report_type": report_type}
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_generated_report_is_signed_verified_and_tenant_scoped():
    _reset_schema()
    with TestClient(app) as client:
        account = _signup(client, "reports@example.com", "Reports org")
        headers = _headers(account)

        created = _create_report(client, headers)
        report = created["report"]
        signature = created["signature"]

        assert report["schema"] == "accessproof.control_plane_report/v1"
        assert report["organization_id"] == account["organization_id"]
        assert report["scope"]["tenant_scoped"] is True
        assert report["evidence_levels"]["control_plane_state"] == (
            "DIRECTLY_OBSERVED_BY_ACCESSPROOF"
        )
        assert report["evidence_levels"]["guard_decisions"] == "NOT_OBSERVED"
        assert report["evidence_levels"]["revocation_to_first_denial_timing"] == "NOT_OBSERVED"
        assert report["summary"]["decisions_24h"]["telemetry"] == "NO_DATA"
        assert signature["algorithm"] == "Ed25519"
        assert signature["payload_sha256"] == created["verification"]["report_hash"]

        verification = client.get(
            f"/api/v1/current/reports/{report['report_id']}/verify", headers=headers
        )
        assert verification.status_code == 200, verification.text
        assert verification.json()["verified"] is True
        assert verification.json()["signature_valid"] is True
        assert verification.json()["scope_valid"] is True
        assert verification.json()["expired"] is False

        listing = client.get("/api/v1/current/reports", headers=headers)
        assert listing.status_code == 200
        assert [row["id"] for row in listing.json()] == [report["report_id"]]

        downloaded = client.get(
            f"/api/v1/current/reports/{report['report_id']}/download", headers=headers
        )
        assert downloaded.status_code == 200
        assert "attachment" in downloaded.headers["content-disposition"]
        body = downloaded.json()
        assert body["report"]["report_id"] == report["report_id"]
        assert body["signature"]["signature"] == signature["signature"]

        other = _signup(client, "reports-other@example.com", "Other reports org")
        assert client.get(
            f"/api/v1/current/reports/{report['report_id']}", headers=_headers(other)
        ).status_code == 404
        assert client.get(
            f"/api/v1/current/reports/{report['report_id']}/verify", headers=_headers(other)
        ).status_code == 404
        assert client.get(
            f"/api/v1/current/reports/{report['report_id']}/download", headers=_headers(other)
        ).status_code == 404


def test_tampered_report_payload_fails_verification():
    _reset_schema()
    with TestClient(app) as client:
        account = _signup(client, "tamper@example.com", "Tamper org")
        headers = _headers(account)
        report_id = _create_report(client, headers)["report"]["report_id"]

        with SessionLocal() as db:
            row = db.get(ControlPlaneReport, report_id)
            payload = json.loads(row.payload_json)
            payload["summary"]["applications_registered"] = 999
            row.payload_json = json.dumps(payload, sort_keys=True)
            db.commit()

        verification = client.get(
            f"/api/v1/current/reports/{report_id}/verify", headers=headers
        )
        assert verification.status_code == 200
        assert verification.json()["signature_valid"] is False
        assert verification.json()["verified"] is False


def test_expired_report_is_not_verified_but_remains_readable():
    _reset_schema()
    with TestClient(app) as client:
        account = _signup(client, "expiry@example.com", "Expiry org")
        headers = _headers(account)
        report_id = _create_report(client, headers)["report"]["report_id"]

        with SessionLocal() as db:
            row = db.get(ControlPlaneReport, report_id)
            row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            db.commit()

        verification = client.get(
            f"/api/v1/current/reports/{report_id}/verify", headers=headers
        )
        assert verification.status_code == 200
        assert verification.json()["expired"] is True
        assert verification.json()["signature_valid"] is True
        assert verification.json()["verified"] is False

        read = client.get(f"/api/v1/current/reports/{report_id}", headers=headers)
        assert read.status_code == 200
        assert read.json()["verification"]["verified"] is False


def test_report_omits_raw_subjects_and_resource_identifiers():
    _reset_schema()
    with TestClient(app) as client:
        account = _signup(client, "privacy@example.com", "Privacy org")
        headers = _headers(account)
        created = _create_report(client, headers, report_type="AUTHORIZATION_ACTIVITY")
        report = created["report"]
        limitations = " ".join(report["limitations"])
        assert "raw employee identifiers" in limitations
        assert "document contents" in limitations
        assert report["decisions"]["recent"] == []
        assert report["evidence_levels"]["guard_decisions"] == "NOT_OBSERVED"


def test_dashboard_reports_no_data_instead_of_zero_coverage():
    _reset_schema()
    with TestClient(app) as client:
        account = _signup(client, "dashboard@example.com", "Dashboard org")
        headers = _headers(account)
        dashboard = client.get("/api/v1/current/dashboard", headers=headers)
        assert dashboard.status_code == 200, dashboard.text
        protection = dashboard.json()["protection"]

        assert protection["applications_registered"] == 0
        assert protection["applications_protected_verified"] == 0
        assert protection["decisions_24h"]["telemetry"] == "NO_DATA"
        assert protection["decisions_24h"]["total"] == 0
        assert protection["latest_decision_at"] is None
        assert protection["sources_fresh"] == 0
