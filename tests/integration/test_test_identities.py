"""Permanent coverage for credential-safe identity-backed runner jobs."""
from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, TestIdentity as DbTestIdentity, TestRun as DbTestRun, engine, SessionLocal


def _setup(client: TestClient):
    signup = client.post("/api/v1/auth/signup", json={"email":"identity@example.com","password":"correct horse battery staple","organization_name":"Identity Org"}).json()
    headers = {"Authorization": f"Bearer {signup['session_token']}", "X-Organization-ID": signup["organization_id"]}
    project = client.post("/api/v1/projects", headers=headers, json={"name":"Identity Project"}).json()["id"]
    suite = client.post("/api/v1/suites", headers=headers, json={"project_id":project,"name":"Revoke","scenario":{"name":"direct_user_revoke","maximum_slo_seconds":30,"timeout_seconds":120}}).json()["id"]
    registration = client.post("/api/v1/runners/registrations", headers=headers, json={"project_id":project}).json()["registration_token"]
    runner = client.post("/api/v1/runners/exchange", json={"registration_token":registration,"name":"identity-runner"}).json()
    return headers, project, suite, runner


def test_identity_credentials_are_encrypted_and_resolved_only_in_runner_lease():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        headers, project, suite, runner = _setup(client)
        created=[]
        for name, subject, token in (("Alice","alice-oid","alice-secret-token"),("Bob","bob-oid","bob-secret-token")):
            response=client.post("/api/v1/test-identities",headers=headers,json={"project_id":project,"display_name":name,"subject_id":subject,"credentials":{"access_token":token}})
            assert response.status_code==201
            assert "access_token" not in response.text and token not in response.text
            created.append(response.json()["id"])
        with SessionLocal() as db:
            rows=db.query(DbTestIdentity).all()
            assert all("secret-token" not in row.encrypted_credentials for row in rows if row.encrypted_credentials)
        raw=client.post("/api/v1/runs",headers=headers,json={"project_id":project,"suite_id":suite,"allowed_principal":{"external_id":"x","access_token":"do-not-store"}})
        assert raw.status_code==422
        run=client.post("/api/v1/runs",headers=headers,json={"project_id":project,"suite_id":suite,"allowed_identity_id":created[0],"denied_identity_id":created[1]}).json()
        with SessionLocal() as db:
            stored=db.get(DbTestRun,run["id"])
            assert "secret-token" not in stored.allowed_principal_json
            assert stored.allowed_identity_id==created[0]
        lease=client.post("/api/v1/runners/lease",headers={"Authorization": f"Bearer {runner['runner_secret']}"},json={"runner_id":runner["runner_id"]}).json()["job"]
        assert lease["allowed_principal"]["access_token"]=="alice-secret-token"
        assert lease["denied_principal"]["access_token"]=="bob-secret-token"
