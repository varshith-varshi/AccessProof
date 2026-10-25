"""Provider event reordering must not resurrect a revoked grant at the same revision."""
import json
import pytest
from sqlalchemy import select
from apps.api.accessproof_api.db import (
    Base, SessionLocal, engine, Organization, Project, SourceConnection,
    GuardSubject, GuardResource, GuardPermissionEvent, GuardEffectiveAccess,
)
from apps.api.accessproof_api.guard_pipeline import process_guard_event


@pytest.mark.parametrize("transitions", [
    ("grant_upsert", "grant_revoke", "grant_upsert"),
    ("grant_revoke", "grant_upsert"),
])
def test_equal_revision_stale_upsert_cannot_undo_revoke(transitions):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="redteam revision replay")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="synthetic")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id,
            provider="google-drive", name="synthetic", boundary="root",
        )
        subject = GuardSubject(
            organization_id=org.id, provider="google-drive",
            provider_subject_id="redteam-employee", status="active",
        )
        db.add_all([source, subject])
        db.flush()
        resource = GuardResource(
            organization_id=org.id, source_id=source.id,
            provider_resource_id="secret", scope="read",
        )
        db.add(resource)
        db.commit()
        for i, change_type in enumerate(transitions):
            event = GuardPermissionEvent(
                organization_id=org.id, source_id=source.id, provider="google-drive",
                subject_id=subject.id, resource_id=resource.id, provider_revision=42,
                change_type=change_type, dedupe_key=f"redteam-order-{i}",
                processing_status="queued",
                mutation_json=json.dumps({
                    "grant_key": "same-grant", "principal_type": "subject",
                    "scope": "read", "grant_effect": "allow",
                    "snapshot_complete": True,
                }),
            )
            db.add(event)
            db.commit()
            process_guard_event(db, event.id)
        state = db.scalar(select(GuardEffectiveAccess).where(
            GuardEffectiveAccess.organization_id == org.id,
            GuardEffectiveAccess.resource_id == resource.id,
        ))
        assert state is not None and state.decision == "deny", state.decision if state else None


@pytest.mark.parametrize("transitions", [
    ("membership_upsert", "membership_revoke", "membership_upsert"),
    ("membership_revoke", "membership_upsert"),
])
def test_equal_revision_group_readd_cannot_undo_membership_removal(transitions):
    from apps.api.accessproof_api.db import GuardGroup, GuardPermissionGrant
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="redteam group replay")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="synthetic")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id,
            provider="google-drive", name="synthetic", boundary="root",
        )
        subject = GuardSubject(
            organization_id=org.id, provider="google-drive",
            provider_subject_id="redteam-employee", status="active",
        )
        group = GuardGroup(
            organization_id=org.id, provider="google-drive",
            provider_group_id="sensitive-group", status="active",
        )
        db.add_all([source, subject, group])
        db.flush()
        resource = GuardResource(
            organization_id=org.id, source_id=source.id,
            provider_resource_id="secret", scope="read",
        )
        db.add(resource)
        db.flush()
        db.add(GuardPermissionGrant(
            organization_id=org.id, source_id=source.id,
            resource_id=resource.id, grant_key="group-grant",
            principal_type="group", principal_id=group.id,
            effect="allow", scope="read", active=True, provider_revision=40,
        ))
        db.commit()
        for i, change_type in enumerate(transitions):
            event = GuardPermissionEvent(
                organization_id=org.id, source_id=source.id,
                provider="google-drive", subject_id=subject.id,
                resource_id=resource.id, provider_revision=42,
                change_type=change_type, dedupe_key=f"group-redteam-{i}",
                processing_status="queued",
                mutation_json=json.dumps({
                    "group_id": "sensitive-group", "scope": "read",
                    "snapshot_complete": True,
                }),
            )
            db.add(event)
            db.commit()
            process_guard_event(db, event.id)
        state = db.scalar(select(GuardEffectiveAccess).where(
            GuardEffectiveAccess.organization_id == org.id,
            GuardEffectiveAccess.resource_id == resource.id,
        ))
        assert state is not None and state.decision == "deny", state.decision if state else None
