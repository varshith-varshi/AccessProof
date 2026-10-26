"""External Graph IDs may not spoof AccessProof internal primary keys."""
from apps.api.accessproof_api.acl_sync import _subjects_for_principal
from apps.api.accessproof_api.db import Base, SessionLocal, engine, Organization, Project, SourceConnection, GuardSubject, GuardGroup, GuardGroupMembership


def test_microsoft_external_user_and_group_id_cannot_spoof_internal_ids():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="ID collision test")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="test")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id, name="Graph",
            provider="microsoft365", boundary="root",
        )
        alice = GuardSubject(
            organization_id=org.id, provider="microsoft365",
            provider_subject_id="entra-real-alice", status="active",
        )
        group = GuardGroup(
            organization_id=org.id, provider="microsoft365",
            provider_group_id="entra-real-group", status="active",
        )
        db.add_all([source, alice, group])
        db.flush()
        db.add(GuardGroupMembership(
            organization_id=org.id, subject_id=alice.id, group_id=group.id, active=True,
        ))
        db.flush()
        assert _subjects_for_principal(
            db, source, "microsoft365", "subject", alice.id, None,
        ) == []
        assert _subjects_for_principal(
            db, source, "microsoft365", "group", group.id, None,
        ) == []
        assert _subjects_for_principal(
            db, source, "microsoft365", "subject", alice.provider_subject_id, None,
        ) == [(alice.id, None)]
        assert _subjects_for_principal(
            db, source, "microsoft365", "subject", alice.id, None, trusted_grant_id=True,
        ) == [(alice.id, None)]
        assert _subjects_for_principal(
            db, source, "microsoft365", "group", group.id, None, trusted_grant_id=True,
        ) == [(alice.id, group.id)]
        assert _subjects_for_principal(
            db, source, "microsoft365", "nonsense", "fake", None,
            trusted_grant_id=True,
        ) == []
