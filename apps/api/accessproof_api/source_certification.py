"""Verify source-specific effective-access certificates without ever issuing them.

No customer-facing endpoint or administrator flag can certify SharePoint / OneDrive.
A provider-validation pipeline must independently verify real-tenant item access,
sign scoped evidence with an operator-managed key, and persist it. Until such a
pipeline exists and is exercised, every Microsoft source remains ineligible.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.accessproof_api.db import SourceConnection, SourceEffectiveCertification


def _source_scope(source: SourceConnection, credentials: dict[str, Any]) -> tuple[str, str] | None:
    provider = (source.provider or "").lower()
    if provider not in {"microsoft365", "sharepoint", "onedrive"}:
        return None
    tenant_id, drive_id, root_id = credentials.get("tenant_id"), credentials.get("drive_id"), credentials.get("test_root_item_id")
    try:
        tenant_id = str(UUID(str(tenant_id)))
    except (TypeError, ValueError, AttributeError):
        return None
    if (tenant_id == "00000000-0000-0000-0000-000000000000"
            or not isinstance(drive_id, str) or not drive_id
            or not isinstance(root_id, str) or not root_id
            or root_id != source.boundary):
        return None
    site_id, list_id = credentials.get("site_id"), credentials.get("list_id")
    owner = credentials.get("owner_object_id")
    if provider == "sharepoint" or (provider == "microsoft365" and site_id and list_id):
        if not isinstance(site_id, str) or not site_id or not isinstance(list_id, str) or not list_id:
            return None
        profile = "sharepoint_list_item_effective"
    elif provider == "onedrive" or (provider == "microsoft365" and owner):
        if not isinstance(owner, str) or not owner:
            return None
        profile = "onedrive_owner_and_sharing_effective"
    else:
        # A drive ID is insufficient to distinguish SharePoint native ACLs
        # from personal OneDrive sharing/ownership semantics.
        return None
    # Stable identifiers only: changing an access token must not invalidate a
    # legitimately verified source; changing drive/site/root/owner MUST.
    identity = {
        "organization_id": source.organization_id, "source_id": source.id,
        "provider": provider, "profile": profile, "tenant_id": tenant_id,
        "drive_id": drive_id, "root_id": root_id, "site_id": site_id,
        "list_id": list_id, "owner_object_id": owner,
    }
    scope_digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return profile, scope_digest


def _certificate_signature(cert: SourceEffectiveCertification, signing_key: str) -> str:
    """Canonical verifier-only signature over the exact immutable scope."""
    payload = {
        "organization_id": cert.organization_id,
        "source_id": cert.source_id,
        "profile": cert.provider_profile,
        "scope_digest": cert.scope_digest,
        "evidence_digest": cert.evidence_digest,
        "verifier_version": cert.verifier_version,
        "certified_at": cert.certified_at.isoformat(),
        "expires_at": cert.expires_at.isoformat(),
    }
    return hmac.new(signing_key.encode(), json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()


def effective_source_certified(db: Session, source: SourceConnection, credentials: dict[str, Any]) -> bool:
    """Never authorize from source metadata, a UI boolean, or expired evidence."""
    scope = _source_scope(source, credentials)
    if scope is None or source.status != "connected" or source.last_validated_at is None:
        return False
    # Separate from public/auth session and report signing secrets. No default,
    # including in development, may accidentally mint a provider certificate.
    signing_key = os.getenv("ACCESSPROOF_SOURCE_CERTIFICATION_HMAC_KEY", "")
    if len(signing_key) < 32 or any(marker in signing_key.lower() for marker in ("development", "change-me", "example", "placeholder")):
        return False
    cert = db.scalar(select(SourceEffectiveCertification).where(
        SourceEffectiveCertification.organization_id == source.organization_id,
        SourceEffectiveCertification.source_id == source.id,
    ))
    if cert is None or cert.status != "verified" or cert.verifier_version != "provider-live-v1":
        return False
    if cert.provider_profile != scope[0] or not hmac.compare_digest(cert.scope_digest, scope[1]):
        return False
    now = datetime.now(timezone.utc)
    issued = cert.certified_at.replace(tzinfo=timezone.utc) if cert.certified_at.tzinfo is None else cert.certified_at
    expires = cert.expires_at.replace(tzinfo=timezone.utc) if cert.expires_at.tzinfo is None else cert.expires_at
    if (issued > now or expires <= now or (expires - issued).total_seconds() > 14 * 86400
            or len(cert.evidence_digest) != 64 or not all(c in "0123456789abcdef" for c in cert.evidence_digest)):
        return False
    return hmac.compare_digest(cert.signature, _certificate_signature(cert, signing_key))
