"""Automatic, directory-verified Microsoft Entra identity resolution.

Why this is sufficient evidence (see docs/adr/ADR-0007-automatic-identity-resolution.md):

* Microsoft directory sync reads every user from Microsoft Graph with the
  SOURCE'S OWN credentials, which are bound to one tenant. The Graph user
  ``id`` is the Entra object id (``oid``) that Entra puts in that employee's
  signed tokens, and it is the same ``id`` Graph reports for SharePoint grants
  (``grantedToV2.user.id``), so ACLs and identities share one immutable key.
* The Guard still verifies every employee token itself (signature, issuer,
  audience, tenant, expiry) and resolves only bindings delivered here.

So an ACTIVE MEMBER account read from the source's tenant is bound
``(issuer=https://login.microsoftonline.com/<tid>/v2.0, subject=<oid>,
tenant=<tid>) -> that principal`` without any administrator action. Nothing
here grants document access: authorization still requires current ACL
evidence for that principal.

Fail-closed rules:
* guests, disabled/removed and unclassifiable accounts are never bound
  (an existing automatic binding is SUSPENDED);
* a principal without a recorded directory tenant, or from another tenant,
  is never bound;
* a manual mapping that contradicts directory evidence becomes CONFLICT
  (denied) and is audited, never silently replaced;
* an administrator's own REVOKED/SUSPENDED/VERIFIED decision on a mapping is
  never overridden by automation (``verified_by_user_id`` is set).
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from apps.api.accessproof_api.db import AuditEvent, GuardIdentityMapping, GuardSubject, SourceConnection

AUTOMATIC_METHOD = "directory_verified"
MICROSOFT_PROVIDERS = {"microsoft365", "sharepoint", "onedrive"}
_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def entra_issuer(tenant_id: str) -> str:
    """The exact v2.0 issuer Entra writes into tokens for this tenant."""
    return f"https://login.microsoftonline.com/{tenant_id}/v2.0"


def is_guid(value: object) -> bool:
    return isinstance(value, str) and bool(_GUID.match(value))


@dataclass
class ResolutionResult:
    source_id: str
    tenant_id: str
    created: int = 0
    reverified: int = 0
    suspended: int = 0
    unchanged: int = 0
    conflicts: list[str] = field(default_factory=list)   # mapping ids
    skipped_ineligible: int = 0
    skipped_admin_owned: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {"source_id": self.source_id, "tenant_id": self.tenant_id, "created": self.created,
                "reverified": self.reverified, "suspended": self.suspended, "unchanged": self.unchanged,
                "conflicts": len(self.conflicts), "skipped_ineligible": self.skipped_ineligible,
                "skipped_admin_owned": self.skipped_admin_owned}


def eligible(subject: GuardSubject, tenant_id: str) -> bool:
    return (subject.provider == "microsoft365" and subject.status == "active"
            and subject.account_kind == "member" and subject.provider_tenant_id == tenant_id
            and is_guid(subject.provider_subject_id))


def reconcile_microsoft_bindings(db: Session, source: SourceConnection, tenant_id: str,
                                 *, now: datetime | None = None) -> ResolutionResult:
    """Idempotent bulk reconciliation for ONE Microsoft source (no Graph calls).

    Two indexed queries regardless of directory size; rows are only written
    when their state actually changes.
    """
    if source.provider.lower() not in MICROSOFT_PROVIDERS or not is_guid(tenant_id):
        raise ValueError("AUTOMATIC_IDENTITY_RESOLUTION_REQUIRES_MICROSOFT_TENANT")
    now = now or datetime.now(timezone.utc)
    issuer = entra_issuer(tenant_id)
    result = ResolutionResult(source.id, tenant_id)
    subjects = {
        s.provider_subject_id: s for s in db.scalars(select(GuardSubject).where(
            GuardSubject.organization_id == source.organization_id,
            GuardSubject.provider == "microsoft365",
            GuardSubject.provider_tenant_id == tenant_id,
        ))
    }
    existing = {
        m.oidc_subject: m for m in db.scalars(select(GuardIdentityMapping).where(
            GuardIdentityMapping.organization_id == source.organization_id,
            GuardIdentityMapping.source_id == source.id,
            GuardIdentityMapping.oidc_issuer == issuer,
            GuardIdentityMapping.oidc_tenant_id == tenant_id,
        ))
    }
    new_rows: list[GuardIdentityMapping] = []
    for oid, subject in subjects.items():
        ok = eligible(subject, tenant_id)
        row = existing.get(oid)
        if row is None:
            if ok:
                new_rows.append(GuardIdentityMapping(
                    organization_id=source.organization_id, source_id=source.id,
                    oidc_issuer=issuer, oidc_subject=oid, oidc_tenant_id=tenant_id,
                    source_subject_id=subject.id, status="VERIFIED", method=AUTOMATIC_METHOD,
                    verified_by_user_id=None, verified_at=now,
                ))
                result.created += 1
            else:
                result.skipped_ineligible += 1
            continue
        _reconcile_existing(row, subject, ok, now, result)
    # Automatic bindings whose principal vanished from this tenant's directory.
    for oid, row in existing.items():
        if oid not in subjects and row.method == AUTOMATIC_METHOD and row.verified_by_user_id is None \
                and row.status == "VERIFIED":
            row.status = "SUSPENDED"
            result.suspended += 1
    if new_rows:
        db.add_all(new_rows)
    db.flush()
    _audit_reconciliation(db, source, result)
    return result


def _audit_reconciliation(db: Session, source: SourceConnection, result: ResolutionResult) -> None:
    """Audit every state change (counts only; no names, emails or object ids).

    Each conflict gets its own event so an administrator can investigate it.
    An unchanged reconciliation writes nothing."""
    if result.created or result.reverified or result.suspended or result.conflicts:
        summary = result.as_dict()
        db.add(AuditEvent(organization_id=source.organization_id, actor_user_id=None,
                          action="identity_resolution.reconciled", target_type="source", target_id=source.id,
                          metadata_json=json.dumps({k: v for k, v in summary.items() if k != "tenant_id"},
                                                   sort_keys=True)))
    for mapping_id in result.conflicts:
        db.add(AuditEvent(organization_id=source.organization_id, actor_user_id=None,
                          action="identity_mapping.conflict_detected", target_type="identity_mapping",
                          target_id=mapping_id, metadata_json=json.dumps({"source_id": source.id,
                                                                          "method": "directory_reconciliation"})))


def _reconcile_existing(row: GuardIdentityMapping, subject: GuardSubject, ok: bool,
                        now: datetime, result: ResolutionResult) -> None:
    if row.verified_by_user_id is not None or row.method != AUTOMATIC_METHOD:
        # Administrator-owned row (manual mapping, or an explicit admin decision
        # on an automatic one). Never overwrite it; only flag contradictions.
        if row.source_subject_id != subject.id and row.status == "VERIFIED":
            row.status = "CONFLICT"
            result.conflicts.append(row.id)
        else:
            result.skipped_admin_owned += 1
        return
    if row.source_subject_id != subject.id:
        # Cannot happen while (org, provider, provider_subject_id) is unique;
        # refuse to guess if the schema ever changes.
        if row.status != "CONFLICT":
            row.status = "CONFLICT"
            result.conflicts.append(row.id)
        return
    if ok and row.status != "VERIFIED" and row.status in {"SUSPENDED"}:
        row.status, row.verified_at, row.revoked_at = "VERIFIED", now, None
        result.reverified += 1
    elif not ok and row.status == "VERIFIED":
        row.status = "SUSPENDED"
        result.suspended += 1
    else:
        result.unchanged += 1


def identity_version(db: Session, organization_id: str) -> str:
    """Cheap fingerprint of everything that shapes a Guard's identity envelope.

    Aggregates only (indexed); every status/binding change bumps updated_at.
    Guards additionally force a full refresh periodically, so a change this
    fingerprint could miss cannot persist indefinitely.
    """
    m_count, m_max = db.execute(select(func.count(GuardIdentityMapping.id), func.max(GuardIdentityMapping.updated_at))
                                .where(GuardIdentityMapping.organization_id == organization_id)).one()
    s_count, s_max = db.execute(select(func.count(GuardSubject.id), func.max(GuardSubject.updated_at))
                                .where(GuardSubject.organization_id == organization_id)).one()
    c_count = db.scalar(select(func.count(SourceConnection.id)).where(SourceConnection.organization_id == organization_id))
    raw = f"{m_count}|{m_max}|{s_count}|{s_max}|{c_count}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def resolution_summary(db: Session, organization_id: str) -> dict[str, Any]:
    """Counts for the administrator's Identity Resolution view (no PII)."""
    rows = db.execute(select(GuardIdentityMapping.method, GuardIdentityMapping.status, func.count())
                      .where(GuardIdentityMapping.organization_id == organization_id)
                      .group_by(GuardIdentityMapping.method, GuardIdentityMapping.status)).all()
    by: dict[str, dict[str, int]] = {}
    for method, status, count in rows:
        by.setdefault(method, {})[status] = int(count)
    subjects = db.execute(select(GuardSubject.account_kind, GuardSubject.status, func.count())
                          .where(GuardSubject.organization_id == organization_id,
                                 GuardSubject.provider == "microsoft365")
                          .group_by(GuardSubject.account_kind, GuardSubject.status)).all()
    directory: dict[str, int] = {}
    for kind, status, count in subjects:
        directory[f"{kind or 'unrecorded'}:{status}"] = int(count)
    automatic = by.get(AUTOMATIC_METHOD, {})
    return {
        "automatic": {"verified": automatic.get("VERIFIED", 0), "suspended": automatic.get("SUSPENDED", 0),
                      "conflict": automatic.get("CONFLICT", 0)},
        "manual": {m: s for m, s in by.items() if m != AUTOMATIC_METHOD},
        "conflicts": sum(s.get("CONFLICT", 0) for s in by.values()),
        "directory_principals": directory,
        "guests_not_bound": sum(v for k, v in directory.items() if k.startswith("guest:")),
    }
