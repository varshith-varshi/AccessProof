from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from apps.api.accessproof_api.app import app
from apps.api.accessproof_api.db import (
    Base,
    Membership,
    ScimConfiguration,
    ScimIdentity,
    SessionLocal,
    engine,
)
from packages.crypto.secrets import hash_token


def _signup(client: TestClient, email: str, org: str):
    response = client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "StrongPassword123!", "organization_name": org},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    headers = {
        "Authorization": f"Bearer {body['session_token']}",
        "X-Organization-ID": body["organization_id"],
    }
    return body, headers


def test_scim_provision_deactivate_reactivate_and_tenant_isolation():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        owner, headers = _signup(client, "owner@example.com", "SCIM Org")
        config = client.put(
            "/api/v1/auth/scim/config",
            headers=headers,
            json={"default_role": "ENGINEER", "enabled": True},
        )
        assert config.status_code == 200, config.text
        token = config.json()["scim_token"]
        scim_headers = {"Authorization": f"Bearer {token}"}

        with SessionLocal() as db:
            stored = db.get(ScimConfiguration, owner["organization_id"])
            assert stored is not None
            assert stored.token_hash == hash_token(token)
            assert token not in stored.token_hash

        service = client.get("/scim/v2/ServiceProviderConfig", headers=scim_headers)
        assert service.status_code == 200
        assert service.json()["patch"]["supported"] is True
        resource_types = client.get("/scim/v2/ResourceTypes", headers=scim_headers)
        assert resource_types.status_code == 200
        assert {row["name"] for row in resource_types.json()["Resources"]} == {"User", "Group"}
        schemas = client.get("/scim/v2/Schemas", headers=scim_headers)
        assert schemas.status_code == 200
        assert any(row["name"] == "AccessProofGroupRole" for row in schemas.json()["Resources"])

        created = client.post(
            "/scim/v2/Users",
            headers=scim_headers,
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "externalId": "idp-123",
                "userName": "new.user@example.com",
                "active": True,
            },
        )
        assert created.status_code == 201, created.text
        user = created.json()
        assert user["userName"] == "new.user@example.com"
        assert user["active"] is True
        assert user["roles"] == [{"value": "ENGINEER"}]
        scim_id = user["id"]

        listed = client.get(
            "/scim/v2/Users?filter=userName%20eq%20%22new.user%40example.com%22",
            headers=scim_headers,
        )
        assert listed.status_code == 200
        assert listed.json()["totalResults"] == 1
        assert listed.json()["Resources"][0]["id"] == scim_id

        with SessionLocal() as db:
            identity = db.get(ScimIdentity, scim_id)
            membership = db.scalar(
                select(Membership).where(
                    Membership.organization_id == owner["organization_id"],
                    Membership.user_id == identity.user_id,
                )
            )
            assert membership is not None and membership.role == "ENGINEER"

        deactivated = client.patch(
            f"/scim/v2/Users/{scim_id}",
            headers=scim_headers,
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "Replace", "path": "active", "value": False}],
            },
        )
        assert deactivated.status_code == 200, deactivated.text
        assert deactivated.json()["active"] is False

        reactivated = client.patch(
            f"/scim/v2/Users/{scim_id}",
            headers=scim_headers,
            json={"Operations": [{"op": "Replace", "path": "active", "value": True}]},
        )
        assert reactivated.status_code == 200
        assert reactivated.json()["active"] is True
        assert reactivated.json()["roles"] == [{"value": "ENGINEER"}]

        other, other_headers = _signup(client, "other-owner@example.com", "Other Org")
        other_cfg = client.put(
            "/api/v1/auth/scim/config", headers=other_headers, json={"default_role": "VIEWER"}
        )
        other_token = other_cfg.json()["scim_token"]
        isolated = client.get(
            f"/scim/v2/Users/{scim_id}", headers={"Authorization": f"Bearer {other_token}"}
        )
        assert isolated.status_code == 404

        deleted = client.delete(f"/scim/v2/Users/{scim_id}", headers=scim_headers)
        assert deleted.status_code == 204
        after = client.get(f"/scim/v2/Users/{scim_id}", headers=scim_headers)
        assert after.status_code == 200
        assert after.json()["active"] is False


def test_scim_rejects_owner_autoprovisioning_and_bad_filter():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        _, headers = _signup(client, "owner2@example.com", "SCIM Guard Org")
        invalid = client.put(
            "/api/v1/auth/scim/config", headers=headers, json={"default_role": "OWNER"}
        )
        assert invalid.status_code == 422
        config = client.put(
            "/api/v1/auth/scim/config", headers=headers, json={"default_role": "VIEWER"}
        )
        token = config.json()["scim_token"]
        response = client.get(
            "/scim/v2/Users?filter=displayName%20eq%20%22Alice%22",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 400
        assert response.json()["scimType"] == "invalidFilter"


def test_scim_groups_membership_role_mapping_conflict_and_fallback():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    role_schema = "urn:accessproof:params:scim:schemas:extension:role:2.0:Group"
    with TestClient(app) as client:
        owner, headers = _signup(client, "group-owner@example.com", "SCIM Groups Org")
        config = client.put(
            "/api/v1/auth/scim/config",
            headers=headers,
            json={"default_role": "VIEWER", "enabled": True},
        )
        assert config.status_code == 200, config.text
        scim_headers = {"Authorization": f"Bearer {config.json()['scim_token']}"}

        created_user = client.post(
            "/scim/v2/Users",
            headers=scim_headers,
            json={
                "userName": "engineer.user@example.com",
                "externalId": "idp-user-1",
                "active": True,
            },
        )
        assert created_user.status_code == 201, created_user.text
        scim_user = created_user.json()
        assert scim_user["roles"] == [{"value": "VIEWER"}]

        engineering = client.post(
            "/scim/v2/Groups",
            headers=scim_headers,
            json={
                "displayName": "Engineering",
                "externalId": "idp-group-eng",
                role_schema: {"role": "ENGINEER"},
                "members": [{"value": scim_user["id"]}],
            },
        )
        assert engineering.status_code == 201, engineering.text
        group = engineering.json()
        assert group[role_schema]["role"] == "ENGINEER"
        assert group["members"][0]["value"] == scim_user["id"]

        refreshed_user = client.get(f"/scim/v2/Users/{scim_user['id']}", headers=scim_headers)
        assert refreshed_user.status_code == 200
        assert refreshed_user.json()["roles"] == [{"value": "ENGINEER"}]

        deactivated = client.patch(
            f"/scim/v2/Users/{scim_user['id']}",
            headers=scim_headers,
            json={"Operations": [{"op": "Replace", "path": "active", "value": False}]},
        )
        assert deactivated.status_code == 200
        assert deactivated.json()["active"] is False
        reactivated = client.patch(
            f"/scim/v2/Users/{scim_user['id']}",
            headers=scim_headers,
            json={"Operations": [{"op": "Replace", "path": "active", "value": True}]},
        )
        assert reactivated.status_code == 200
        assert reactivated.json()["roles"] == [{"value": "ENGINEER"}]

        auditors = client.post(
            "/scim/v2/Groups",
            headers=scim_headers,
            json={
                "displayName": "Auditors",
                role_schema: {"role": "AUDITOR"},
            },
        )
        assert auditors.status_code == 201, auditors.text
        auditor_group_id = auditors.json()["id"]

        conflict = client.patch(
            f"/scim/v2/Groups/{auditor_group_id}",
            headers=scim_headers,
            json={
                "Operations": [
                    {"op": "Add", "path": "members", "value": [{"value": scim_user["id"]}]}
                ]
            },
        )
        assert conflict.status_code == 409, conflict.text
        assert conflict.json()["scimType"] == "mutability"

        removed = client.patch(
            f"/scim/v2/Groups/{group['id']}",
            headers=scim_headers,
            json={
                "Operations": [{"op": "Remove", "path": f'members[value eq "{scim_user["id"]}"]'}]
            },
        )
        assert removed.status_code == 200, removed.text
        assert removed.json()["members"] == []
        fallback_user = client.get(f"/scim/v2/Users/{scim_user['id']}", headers=scim_headers)
        assert fallback_user.json()["roles"] == [{"value": "VIEWER"}]

        readd = client.patch(
            f"/scim/v2/Groups/{auditor_group_id}",
            headers=scim_headers,
            json={
                "Operations": [
                    {"op": "Add", "path": "members", "value": [{"value": scim_user["id"]}]}
                ]
            },
        )
        assert readd.status_code == 200, readd.text
        assert client.get(f"/scim/v2/Users/{scim_user['id']}", headers=scim_headers).json()[
            "roles"
        ] == [{"value": "AUDITOR"}]

        deleted = client.delete(f"/scim/v2/Groups/{auditor_group_id}", headers=scim_headers)
        assert deleted.status_code == 204
        assert client.get(f"/scim/v2/Users/{scim_user['id']}", headers=scim_headers).json()[
            "roles"
        ] == [{"value": "VIEWER"}]

        listed = client.get(
            "/scim/v2/Groups?filter=displayName%20eq%20%22Engineering%22", headers=scim_headers
        )
        assert listed.status_code == 200
        assert listed.json()["totalResults"] == 1

        other, other_headers = _signup(client, "group-other@example.com", "SCIM Other Groups")
        other_cfg = client.put(
            "/api/v1/auth/scim/config", headers=other_headers, json={"default_role": "VIEWER"}
        )
        isolated = client.get(
            f"/scim/v2/Groups/{group['id']}",
            headers={"Authorization": f"Bearer {other_cfg.json()['scim_token']}"},
        )
        assert isolated.status_code == 404

        with SessionLocal() as db:
            identity = db.get(ScimIdentity, scim_user["id"])
            membership = db.scalar(
                select(Membership).where(
                    Membership.organization_id == owner["organization_id"],
                    Membership.user_id == identity.user_id,
                )
            )
            assert membership is not None and membership.role == "VIEWER"


def test_scim_group_role_never_allows_owner():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    role_schema = "urn:accessproof:params:scim:schemas:extension:role:2.0:Group"
    with TestClient(app) as client:
        _, headers = _signup(client, "group-guard@example.com", "SCIM Group Guard")
        config = client.put(
            "/api/v1/auth/scim/config", headers=headers, json={"default_role": "VIEWER"}
        )
        scim_headers = {"Authorization": f"Bearer {config.json()['scim_token']}"}
        response = client.post(
            "/scim/v2/Groups",
            headers=scim_headers,
            json={"displayName": "Owners", role_schema: {"role": "OWNER"}},
        )
        assert response.status_code == 422
