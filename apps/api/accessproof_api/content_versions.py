"""Current document versions delivered to Guards (cached-chunk freshness).

A signed chunk attestation proves which bytes a document version contained,
not that the version is still current. A chunk or answer cache can replay an
older version for up to the attestation lifetime (<= 3600 s). The Guard closes
that gap by refusing chunks whose ``content_version`` is not a current
provider version of the document.

For Microsoft Graph the RAG's ``content_version`` is the driveItem ``eTag``
(the reference ingestion contract) or ``cTag``; both current values are
delivered, so either convention matches while any older value is refused.

A source is versioned ONLY when every live document in it has a recorded
version. A partially versioned source would deny every unversioned document,
so it is omitted (legacy behaviour) until the ACL sync backfills it.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.accessproof_api.db import GuardResource, SourceConnection

MICROSOFT = {"microsoft365", "sharepoint", "onedrive"}
VERSION_KEYS = ("eTag", "cTag")


def document_versions(metadata: dict[str, Any]) -> list[str]:
    return sorted({str(metadata[k]) for k in VERSION_KEYS if isinstance(metadata.get(k), str) and metadata[k]})


def needs_backfill(db: Session, source: SourceConnection) -> bool:
    for row in db.scalars(select(GuardResource).where(
        GuardResource.organization_id == source.organization_id,
        GuardResource.source_id == source.id,
        GuardResource.resource_type == "document",
    )):
        metadata = json.loads(row.metadata_json or "{}")
        if not metadata.get("deleted") and not document_versions(metadata):
            return True
    return False


def resource_versions_envelope(db: Session, organization_id: str, source_ids: list[str]) -> dict[str, Any]:
    """{"sources": [...complete sources], "items": [...], "digest": "..."}."""
    sources: list[str] = []
    items: list[dict[str, Any]] = []
    for source in db.scalars(select(SourceConnection).where(
        SourceConnection.organization_id == organization_id,
        SourceConnection.id.in_(sorted(set(source_ids))),
    ).order_by(SourceConnection.id)):
        if source.provider.lower() not in MICROSOFT:
            continue
        found: list[dict[str, Any]] = []
        complete = True
        for row in db.scalars(select(GuardResource).where(
            GuardResource.organization_id == organization_id,
            GuardResource.source_id == source.id,
            GuardResource.resource_type == "document",
        ).order_by(GuardResource.provider_resource_id)):
            metadata = json.loads(row.metadata_json or "{}")
            if metadata.get("deleted"):
                continue  # deleted: no current version, the Guard refuses it as unknown
            versions = document_versions(metadata)
            if not versions:
                complete = False
                break
            found.append({"source_id": source.id, "resource_id": row.provider_resource_id, "versions": versions})
        if complete:
            sources.append(source.id)
            items.extend(found)
    digest = hashlib.sha256(json.dumps([sources, items], sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]
    return {"sources": sources, "items": items, "digest": digest}
