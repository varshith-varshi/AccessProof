"""Cross-tenant BOLA/IDOR sweep over every parameterized API route.

Tenant A's OWNER calls every route that takes a path parameter, substituting
every object id owned by tenant B (including application ids) into every slot,
so type-confused ids are exercised too. No call may succeed, and tenant B's
data must be unchanged afterwards.

Writes are sent with an empty body. Routes that answer 422 validate their body
before reaching authorization, so this sweep cannot see their authorization
check. Each was reviewed by hand (scoped by organization, or by Guard/runner
credential) and is pinned below: a NEW 422 route fails this test until it is
reviewed.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api import app as api
from apps.api.accessproof_api import db as m

PASSWORD = "correct horse battery staple"

REVIEWED_VALIDATION_FIRST_ROUTES = {
    "DELETE /api/v1/projects/{project_id}",
    "GET /api/v1/runners/runs/{run_id}/cancel-status",
    "PATCH /api/v1/current/ai-applications/{application_id}/mode",
    "PATCH /api/v1/current/identity-mappings/{mapping_id}",
    "PATCH /api/v1/organization/members/{membership_id}",
    "POST /api/v1/current/ai-applications/{application_id}/protection/challenge",
    "POST /api/v1/current/ai-applications/{application_id}/verification",
    "POST /api/v1/current/ai-applications/{application_id}/verification-approvals",
    "POST /api/v1/guards/{guard_id}/rag-challenges/{challenge_id}/cutover",
    "POST /api/v1/guards/{guard_id}/rag-challenges/{challenge_id}/submit",
}


def _signup(client: TestClient, email: str, organization: str) -> tuple[str, dict[str, str]]:
    body = client.post("/api/v1/auth/signup", json={
        "email": email, "password": PASSWORD, "organization_name": organization}).json()
    org = body["organization_id"]
    return org, {"Authorization": f"Bearer {body['session_token']}", "X-Organization-ID": org}


def _seed_victim_objects(org: str) -> set[str]:
    now = datetime.now(timezone.utc)
    with m.SessionLocal() as db:
        api.set_tenant_context(db, org)
        project = m.Project(organization_id=org, name="victim project")
        db.add(project)
        db.flush()
        source = m.SourceConnection(organization_id=org, project_id=project.id, name="SharePoint",
                                    provider="sharepoint", boundary="root", status="connected")
        guard = m.GuardRegistration(organization_id=org, name="guard", status="enrolled", enrolled_at=now)
        db.add_all([source, guard])
        db.flush()
        application = m.AIApplication(organization_id=org, application_id="victim-rag", name="RAG",
                                      guard_id=guard.id, source_id=source.id,
                                      adapter_type="accessproof-gateway", mode="protect_pending")
        suite = m.TestSuite(organization_id=org, project_id=project.id, name="suite", scenario_json="{}")
        db.add_all([application, suite])
        db.flush()
        run = m.TestRun(organization_id=org, project_id=project.id, suite_id=suite.id)
        db.add(run)
        db.flush()
        db.add_all([
            m.Report(organization_id=org, project_id=project.id, run_id=run.id, report_hash="h" * 64),
            m.Runner(organization_id=org, project_id=project.id, name="runner", credential_hash="x" * 64),
            m.ScimGroup(organization_id=org, display_name="group"),
            m.WebhookEndpoint(organization_id=org, url="https://example.invalid/hook",
                              secret_hash="x", encrypted_secret="x"),
            m.RAGRouteChallenge(organization_id=org, application_row_id=application.id, guard_id=guard.id,
                                source_id=source.id, nonce_digest="n" * 64, configuration_fingerprint="f",
                                deployment_sha256="d" * 64, route_sha256="r" * 64,
                                expires_at=now + timedelta(hours=1)),
        ])
        db.commit()
        ids = {org}
        for mapper in m.Base.registry.mappers:
            cls = mapper.class_
            if "organization_id" not in {column.name for column in cls.__table__.columns}:
                continue
            for row in db.scalars(select(cls).where(cls.organization_id == org)):
                for attr in ("id", "application_id"):
                    value = getattr(row, attr, None)
                    if isinstance(value, str):
                        ids.add(value)
    return ids


def test_no_route_serves_or_mutates_another_tenants_objects():
    m.Base.metadata.drop_all(m.engine)
    m.Base.metadata.create_all(m.engine)
    findings: list[dict[str, object]] = []
    validation_first: set[str] = set()
    requests = 0
    with TestClient(api.app) as client:
        _, attacker = _signup(client, "attacker@example.com", "Alpha Labs")
        victim_org, _ = _signup(client, "victim@example.com", "Bravo Corp")
        victim_ids = _seed_victim_objects(victim_org)
        for route in api.app.routes:
            path = getattr(route, "path", "")
            names = re.findall(r"\{(\w+)\}", path)
            if not names:
                continue
            for method in sorted(set(getattr(route, "methods", set())) - {"HEAD", "OPTIONS"}):
                for object_id in sorted(victim_ids):
                    url = path
                    for name in names:
                        url = url.replace("{" + name + "}", object_id)
                    kwargs: dict[str, object] = {"headers": attacker}
                    if method in {"POST", "PUT", "PATCH"}:
                        kwargs["json"] = {}
                    response = client.request(method, url, **kwargs)
                    requests += 1
                    if 200 <= response.status_code < 300:
                        findings.append({"route": f"{method} {path}", "id": object_id,
                                         "status": response.status_code, "body": response.text[:300]})
                    elif response.status_code == 422:
                        validation_first.add(f"{method} {path}")
    with m.SessionLocal() as db:
        api.set_tenant_context(db, victim_org)
        victim_app = db.scalar(select(m.AIApplication).where(m.AIApplication.application_id == "victim-rag"))
    print(json.dumps({"requests": requests, "victim_ids": len(victim_ids)}))
    assert requests > 500
    assert findings == [], json.dumps(findings, indent=1)
    assert victim_app is not None and victim_app.archived_at is None
    unreviewed = validation_first - REVIEWED_VALIDATION_FIRST_ROUTES
    assert not unreviewed, f"review authorization of validation-first routes: {sorted(unreviewed)}"
