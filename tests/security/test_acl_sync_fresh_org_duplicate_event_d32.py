"""D-32 (found by fresh-customer onboarding on r37): the first full ACL snapshot
of a NEW organization can queue the same permission event twice in one sync
(e.g. two grants resolving to the same subject/resource). The session runs with
autoflush=False, so the duplicate check could not see the still-pending first
event; the next flush raised IntegrityError and the source never completed an
ACL sync (Guard never received a policy, fail closed)."""
from sqlalchemy import func, select

from apps.api.accessproof_api.acl_sync import _event
from apps.api.accessproof_api.db import (
    Base, GuardPermissionEvent, GuardResource, Organization, Project, SessionLocal, SourceConnection, engine,
)


def test_same_event_twice_in_one_sync_is_deduplicated_not_an_integrity_error():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="fresh")
        db.add(org); db.flush()
        project = Project(organization_id=org.id, name="p"); db.add(project); db.flush()
        source = SourceConnection(organization_id=org.id, project_id=project.id, name="s", provider="sharepoint",
                                  boundary="root", status="connected")
        db.add(source); db.flush()
        resource = GuardResource(organization_id=org.id, source_id=source.id, provider_resource_id="item-1")
        db.add(resource); db.flush()
        kwargs = dict(source=source, provider="sharepoint", resource=resource, subject_id="alice",
                      change_type="grant_upserted", revision=1, mutation={"m": 1}, stable="same-stable-key")
        assert _event(db, **kwargs) is True
        assert _event(db, **kwargs) is False          # pending duplicate is seen
        db.flush()                                     # previously: IntegrityError here
        assert db.scalar(select(func.count(GuardPermissionEvent.id))) == 1
