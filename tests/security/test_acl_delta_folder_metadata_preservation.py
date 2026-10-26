"""Sparse provider changes must not rewrite known SharePoint folders as files."""
from sqlalchemy import select

from apps.api.accessproof_api.acl_sync import _resource
from apps.api.accessproof_api.db import Base, SessionLocal, engine, GuardResource, Organization, Project, SourceConnection
from apps.api.accessproof_api.acl_sync import _now


def test_sharepoint_sparse_delta_preserves_folder_type_parent_and_acl_metadata():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="Folder metadata test")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="Project")
        db.add(project)
        db.flush()
        source = SourceConnection(
            organization_id=org.id, project_id=project.id,
            provider="microsoft365", boundary="root", name="SharePoint",
        )
        db.add(source)
        db.flush()
        root = _resource(db, source, "root", {
            "id": "root", "folder": {}, "name": "Root",
        }, _now())
        folder = _resource(db, source, "subfolder", {
            "id": "subfolder", "folder": {}, "name": "Finance",
            "parentReference": {"id": "root", "driveId": "d1"},
        }, _now())
        assert folder.resource_type == "folder"
        assert folder.parent_resource_id == root.id
        folder_id = folder.id
        updated = _resource(db, source, "subfolder", {"id": "subfolder"}, _now())
        assert updated.id == folder_id
        assert updated.resource_type == "folder"
        assert updated.parent_resource_id == root.id
        assert updated.metadata_json and '"name": "Finance"' in updated.metadata_json
        assert db.scalar(select(GuardResource).where(GuardResource.id == folder_id)) is updated
