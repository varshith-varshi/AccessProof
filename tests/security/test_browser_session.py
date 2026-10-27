from fastapi.testclient import TestClient

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import Base, engine


def test_cookie_session_get_allowed_but_mutation_requires_csrf_and_logout_clears_cookie():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        signup = c.post(
            "/api/v1/auth/signup",
            json={
                "email": "cookie@example.com",
                "password": "correct horse battery staple",
                "organization_name": "Cookie Org",
            },
        ).json()
        login = c.post(
            "/api/v1/auth/login",
            json={"email": "cookie@example.com", "password": "correct horse battery staple"},
        )
        assert login.status_code == 200
        org = signup["organization_id"]
        headers = {"X-Organization-ID": org}
        assert c.get("/api/v1/projects", headers=headers).status_code == 200
        assert (
            c.post("/api/v1/projects", headers=headers, json={"name": "blocked"}).status_code == 403
        )
        csrf = c.cookies.get("accessproof_csrf")
        assert csrf
        safe_headers = {**headers, "X-CSRF-Token": csrf}
        assert (
            c.post("/api/v1/projects", headers=safe_headers, json={"name": "allowed"}).status_code
            == 201
        )
        logout = c.post("/api/v1/auth/logout", headers=safe_headers)
        assert logout.status_code == 204
        assert c.get("/api/v1/projects", headers=headers).status_code == 401
