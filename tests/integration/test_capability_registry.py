"""The capability registry must not let support claims outrun evidence."""
import json

from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine
from packages.capability_registry import (
    CAPABILITY_REGISTRY_SCHEMA,
    EvidenceLevel,
    capabilities,
    csv_text,
    release_gate,
    snapshot,
    validate,
)


def _capability(capability_id: str):
    return next(item for item in capabilities() if item.id == capability_id)


def test_registry_is_internally_consistent_and_honest() -> None:
    validate()
    data = snapshot()
    assert data["schema"] == CAPABILITY_REGISTRY_SCHEMA
    assert len({item["id"] for item in data["capabilities"]}) == len(data["capabilities"])
    assert _capability("source.microsoft365").protect_eligible is False
    assert _capability("retrieval.authorized_pgvector").evidence_level is EvidenceLevel.UNIT_VERIFIED
    assert _capability("retrieval.global_ann_post_filter").state.value == "UNSUPPORTED"
    assert _capability("route.native_streaming").state.value == "UNSUPPORTED"
    assert _capability("route.buffered_sse").state.value == "PARTIAL"
    assert _capability("evidence.pdf_package").state.value == "UNSUPPORTED"
    live = [
        item for item in data["capabilities"]
        if item["evidence_level"] in {
            "LIVE_PROVIDER_VERIFIED", "INDEPENDENT_CUSTOMER_VERIFIED",
            "STAGING_VERIFIED", "PRODUCTION_OBSERVED",
        }
    ]
    assert live == []
    assert any(item["id"].startswith("adapter.") for item in data["capabilities"])


def test_release_gate_refuses_broad_production_and_pilot_claims() -> None:
    gate = release_gate()
    assert gate["profiles"]["LAB"]["eligible"] is True
    assert gate["profiles"]["CONSTRAINED_PILOT"]["eligible"] is False
    assert gate["profiles"]["CERTIFIED_PROFILE"]["eligible"] is False
    assert gate["profiles"]["NO_GO"]["eligible"] is True
    assert any("Microsoft" in blocker for blocker in gate["blockers"])
    assert any("pgvector" in blocker for blocker in gate["blockers"])


def test_csv_export_is_machine_readable() -> None:
    rows = csv_text().splitlines()
    header = rows[0].split(",")
    assert header[:6] == ["id", "category", "name", "state", "evidence_level", "protect_eligible"]
    assert len(rows) == len(capabilities()) + 1


def _signup(client, email: str) -> dict:
    return client.post("/api/v1/auth/signup", json={
        "email": email, "password": "correct horse battery staple",
        "organization_name": email,
    }).json()


def test_capability_endpoint_requires_authentication_and_is_tenant_neutral() -> None:
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        assert client.get("/api/v1/current/capabilities").status_code == 401
        account = _signup(client, "capabilities@example.com")
        response = client.get("/api/v1/current/capabilities", headers={
            "Authorization": f"Bearer {account['session_token']}",
            "X-Organization-ID": account["organization_id"],
        })
    assert response.status_code == 200
    body = response.json()
    assert body["schema"] == CAPABILITY_REGISTRY_SCHEMA
    assert body["release_gate"]["profiles"]["CERTIFIED_PROFILE"]["eligible"] is False
    item = next(row for row in body["capabilities"] if row["id"] == "source.microsoft365")
    assert item["protect_eligible"] is False
    # The registry must remain product metadata, never tenant resource data.
    assert "organization_id" not in json.dumps(body)
