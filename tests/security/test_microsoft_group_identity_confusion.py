"""A newly-created Entra group may reuse an old email but not the old membership."""

from apps.api.accessproof_api.acl_sync import _group_for_principal, _subjects_for_principal
from apps.api.accessproof_api.db import (
    Base, engine, SessionLocal, Organization, Project, SourceConnection,
    GuardSubject, GuardGroup, GuardGroupMembership,
)


def test_microsoft_group_email_reuse_never_inherits_old_members():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="Microsoft group reassignment")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="Project")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id, name="Graph",
            provider="microsoft365", boundary="root")
        old_group = GuardGroup(
            organization_id=org.id, provider="microsoft365",
            provider_group_id="old-group-id", provider_email="finance@example.com", status="active")
        employee = GuardSubject(
            organization_id=org.id, provider="microsoft365", provider_subject_id="old-member", status="active")
        db.add_all([source, old_group, employee])
        db.flush()
        db.add(GuardGroupMembership(
            organization_id=org.id, group_id=old_group.id, subject_id=employee.id, active=True))
        db.flush()
        assert _subjects_for_principal(
            db, source, "microsoft365", "group", "new-group-id", "finance@example.com"
        ) == []
        new = _group_for_principal(
            db, source, "microsoft365", "new-group-id", "finance@example.com"
        )
        assert new.id != old_group.id
        assert new.provider_group_id == "new-group-id"
        assert _subjects_for_principal(
            db, source, "microsoft365", "group", "new-group-id", "finance@example.com"
        ) == []
