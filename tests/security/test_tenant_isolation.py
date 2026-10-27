from fastapi.testclient import TestClient
from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine


def signup(client, email, org):
    r = client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "correct horse battery staple", "organization_name": org},
    )
    assert r.status_code == 201
    return r.json()


def h(s):
    return {
        "Authorization": f"Bearer {s['session_token']}",
        "X-Organization-ID": s["organization_id"],
    }


def test_org_a_cannot_fetch_org_b_run_or_infer_metadata():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        a = signup(client, "a@example.com", "Org A")
        b = signup(client, "b@example.com", "Org B")
        pb = client.post("/api/v1/projects", headers=h(b), json={"name": "Secret B"}).json()["id"]
        sb = client.post(
            "/api/v1/suites",
            headers=h(b),
            json={
                "project_id": pb,
                "name": "B Suite",
                "scenario": {
                    "name": "direct_user_revoke",
                    "maximum_slo_seconds": 30,
                    "timeout_seconds": 120,
                },
            },
        ).json()["id"]
        rb = client.post(
            "/api/v1/runs", headers=h(b), json={"project_id": pb, "suite_id": sb}
        ).json()["id"]
        response = client.get(f"/api/v1/runs/{rb}", headers=h(a))
        assert response.status_code == 404
        assert "Secret B" not in response.text and "B Suite" not in response.text


def test_org_id_header_cannot_impersonate_without_membership():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        a = signup(client, "a@example.com", "Org A")
        b = signup(client, "b@example.com", "Org B")
        fake = {
            "Authorization": f"Bearer {a['session_token']}",
            "X-Organization-ID": b["organization_id"],
        }
        r = client.get("/api/v1/projects", headers=fake)
        assert r.status_code == 403
