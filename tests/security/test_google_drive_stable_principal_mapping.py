"""Do not authorize Drive ACLs through recycled emails or suspended subjects."""
from __future__ import annotations

from apps.api.accessproof_api import acl_sync
from apps.api.accessproof_api.config import Settings
from apps.api.accessproof_api.db import (
    Base, GuardGroup, GuardSubject, Organization, Project, SessionLocal,
    SourceConnection, engine,
)


def test_production_google_identity_does_not_reassign_access_via_email(monkeypatch):
    monkeypatch.setattr(acl_sync, "settings", Settings(env="production"))
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="identity-reuse-test")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id,
            name="Drive", provider="google-drive", boundary="root",
        )
        previous = GuardSubject(
            organization_id=org.id, provider="google-drive",
            provider_subject_id="former-google-user",
            primary_email="reused@example.test", status="removed",
        )
        replacement = GuardSubject(
            organization_id=org.id, provider="google-drive",
            provider_subject_id="new-google-user", drive_permission_id="drive-new-user",
            primary_email="reused@example.test", status="active",
        )
        suspended = GuardSubject(
            organization_id=org.id, provider="google-drive",
            provider_subject_id="suspended-user",
            primary_email="suspended@example.test", status="suspended",
        )
        db.add_all([source, previous, replacement, suspended])
        db.flush()

        # The ACL still belongs to the former account. A replacement account
        # with the same email is not entitled to its content.
        assert acl_sync._subjects_for_principal(
            db, source, "google-drive", "subject", "former-google-user",
            "reused@example.test",
        ) == []
        assert acl_sync._subjects_for_principal(
            db, source, "google-drive", "subject", "suspended-user",
            "suspended@example.test",
        ) == []
        assert acl_sync._subjects_for_principal(
            db, source, "google-drive", "subject", "drive-new-user",
            "reused@example.test",
        ) == [(replacement.id, None)]

        trusted_group = GuardGroup(
            organization_id=org.id, provider="google-drive",
            provider_group_id="old-directory-group",
            provider_email="reused-group@example.test", status="active",
        )
        db.add(trusted_group)
        db.flush()
        unexpected = acl_sync._group_for_principal(
            db, source, "google-drive", "new-provider-permission-group",
            "reused-group@example.test",
        )
        # A Drive permission with an unrelated ID never inherits membership
        # merely because it advertises the same mutable email.
        assert unexpected.id != trusted_group.id
        assert unexpected.status == "unknown"

 

def test_trusted_internal_group_id_cannot_cross_customer_boundary(monkeypatch):
    monkeypatch.setattr(acl_sync, "settings", Settings(env="production"))
    from apps.api.accessproof_api.db import GuardGroupMembership
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org_a = Organization(name="tenant-a")
        org_b = Organization(name="tenant-b")
        db.add_all([org_a, org_b])
        db.flush()
        project_a = Project(organization_id=org_a.id, name="project-a")
        db.add(project_a)
        db.flush()
        source_a = SourceConnection(
            organization_id=org_a.id, project_id=project_a.id,
            name="Drive A", provider="google-drive", boundary="root-a",
        )
        employee_b = GuardSubject(
            organization_id=org_b.id, provider="google-drive",
            provider_subject_id="employee-b", drive_permission_id="employee-b-perm",
            status="active",
        )
        group_b = GuardGroup(
            organization_id=org_b.id, provider="google-drive",
            provider_group_id="group-b", drive_permission_id="group-b-perm",
            status="active",
        )
        db.add_all([source_a, employee_b, group_b])
        db.flush()
        db.add(GuardGroupMembership(
            organization_id=org_b.id, subject_id=employee_b.id,
            group_id=group_b.id, active=True,
        ))
        db.flush()
        assert acl_sync._subjects_for_principal(
            db, source_a, "google-drive", "group", group_b.id, None,
            trusted_grant_id=True,
        ) == []
