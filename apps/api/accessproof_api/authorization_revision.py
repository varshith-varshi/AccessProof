"""Signed, monotonic authorization revisions for one Guard application binding.

A revision binds every Guard decision to the exact source ACL cursor, directory
cursor, Guard policy version, narrowing policy and application binding that the
control plane observed when the revision was issued. It deliberately records
content-snapshot revision as ``None``: AccessProof has no independent content
snapshot ledger, and inventing one would be false evidence.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from apps.api.accessproof_api.db import (
    AIApplication,
    AIApplicationSourceBinding,
    AuthorizationRevision,
    AuthorizationRevisionSequence,
    GuardPolicy,
    Organization,
    ProviderSyncCursor,
    SourceConnection,
    utcnow,
)
from packages.crypto.signing import Ed25519Signer

AUTHORIZATION_REVISION_SCHEMA = "accessproof.authorization_revision/v1"
REVISION_LIMITATIONS = [
    "Provider permission modification time is not observed; only the provider change observed by AccessProof is recorded.",
    "Content snapshot revision is NOT_OBSERVED; trusted content lineage is carried separately by source attestations.",
    "A revision is control-plane evidence and does not by itself prove the Guard applied it.",
]


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    checked = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    return checked.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _cursor(db: OrmSession, source_id: str | None, kind: str) -> ProviderSyncCursor | None:
    if not source_id:
        return None
    return db.scalar(select(ProviderSyncCursor).where(
        ProviderSyncCursor.source_id == source_id,
        ProviderSyncCursor.sync_kind == kind,
    ))


def _state(
    db: OrmSession,
    application: AIApplication,
    guard_policy_version: int,
    acl: ProviderSyncCursor | None,
    directory: ProviderSyncCursor | None,
    source: SourceConnection | None,
) -> dict[str, Any]:
    narrowing = {
        "mode": application.mode,
        "adapter_type": application.adapter_type,
        "adapter_contract_version": application.adapter_contract_version,
    }
    return {
        "schema": AUTHORIZATION_REVISION_SCHEMA,
        "organization_id": application.organization_id,
        "application_id": application.application_id,
        "source_id": application.source_id,
        "source_provider": source.provider.lower() if source else None,
        "guard_id": application.guard_id,
        "guard_policy_version": guard_policy_version,
        "acl_revision": acl.last_provider_revision if acl else None,
        "acl_status": acl.status if acl else "never_synced",
        "directory_revision": directory.last_provider_revision if directory else None,
        "directory_status": directory.status if directory else "never_synced",
        "group_membership_revision": directory.last_provider_revision if directory else None,
        "content_snapshot_revision": None,
        "narrowing_policy_revision": _hash(narrowing),
        **narrowing,
    }


def issue_or_reuse_revision(
    db: OrmSession,
    application: AIApplication,
    *,
    signer: Ed25519Signer,
    now: datetime | None = None,
) -> AuthorizationRevision:
    """Return the current revision or append a new signed one after a state change."""
    generated_at = now or utcnow()
    # Serialize allocation per tenant, including first-use sequence creation.
    db.scalar(select(Organization).where(Organization.id == application.organization_id).with_for_update())
    latest = db.scalar(select(AuthorizationRevision).where(
        AuthorizationRevision.organization_id == application.organization_id,
        AuthorizationRevision.application_row_id == application.id,
    ).order_by(AuthorizationRevision.revision.desc()).limit(1))
    policy_version = int(db.scalar(select(func.max(GuardPolicy.version)).where(
        GuardPolicy.organization_id == application.organization_id
    )) or 0)
    acl = _cursor(db, application.source_id, "acl")
    directory = _cursor(db, application.source_id, "directory")
    source = db.get(SourceConnection, application.source_id) if application.source_id else None
    if source is not None and source.organization_id != application.organization_id:
        source = None
    state = _state(db, application, policy_version, acl, directory, source)
    source_ids = list(db.scalars(select(AIApplicationSourceBinding.source_id).where(
        AIApplicationSourceBinding.organization_id == application.organization_id,
        AIApplicationSourceBinding.application_row_id == application.id,
    )).all())
    if application.source_id:
        source_ids.append(application.source_id)
    state["source_states"] = []
    for source_id in sorted(set(source_ids)):
        extra_source = db.get(SourceConnection, source_id)
        if extra_source is None or extra_source.organization_id != application.organization_id:
            raise ValueError("CROSS_TENANT_APPLICATION_SOURCE_BINDING")
        extra_acl = _cursor(db, source_id, "acl")
        extra_dir = _cursor(db, source_id, "directory")
        state["source_states"].append({
            "source_id": source_id, "provider": extra_source.provider.lower(),
            "acl_revision": extra_acl.last_provider_revision if extra_acl else None,
            "acl_status": extra_acl.status if extra_acl else "never_synced",
            "directory_revision": extra_dir.last_provider_revision if extra_dir else None,
            "directory_status": extra_dir.status if extra_dir else "never_synced",
        })
    state_hash = _hash(state)
    if latest is not None and latest.state_hash == state_hash:
        return latest

    sequence = db.scalar(select(AuthorizationRevisionSequence).where(
        AuthorizationRevisionSequence.organization_id == application.organization_id,
        AuthorizationRevisionSequence.application_row_id == application.id,
    ).with_for_update())
    if sequence is None:
        revision_number = 1
        sequence = AuthorizationRevisionSequence(
            organization_id=application.organization_id,
            application_row_id=application.id,
            next_revision=2,
        )
        db.add(sequence)
    else:
        revision_number = sequence.next_revision
        sequence.next_revision += 1
        sequence.updated_at = generated_at

    observed_times = [
        value for value in (
            acl.last_success_at if acl else None,
            directory.last_success_at if directory else None,
        ) if value is not None
    ]
    source_observed_at = min(observed_times) if observed_times else None
    payload: dict[str, Any] = {
        **state,
        "revision": revision_number,
        "previous_revision_hash": latest.revision_hash if latest else None,
        "source_observed_at": _iso(source_observed_at),
        "generated_at": _iso(generated_at),
        "limitations": list(REVISION_LIMITATIONS),
    }
    manifest = signer.sign(payload).as_dict()
    if manifest["payload_sha256"] != _hash(payload):
        raise RuntimeError("AUTHORIZATION_REVISION_SIGNING_MISMATCH")
    row = AuthorizationRevision(
        organization_id=application.organization_id,
        application_row_id=application.id,
        application_id=application.application_id,
        source_id=application.source_id,
        guard_id=application.guard_id,
        revision=revision_number,
        state_hash=state_hash,
        revision_hash=manifest["payload_sha256"],
        previous_revision_hash=latest.revision_hash if latest else None,
        payload_json=json.dumps(payload, sort_keys=True, separators=(",", ":")),
        signing_key_id=manifest["key_id"],
        signature=manifest["signature"],
        signing_public_key=manifest["public_key"],
        signed_manifest_json=json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        source_observed_at=source_observed_at,
        generated_at=generated_at,
    )
    db.add(row)
    db.flush()
    return row


def revision_envelope(row: AuthorizationRevision) -> dict[str, Any]:
    """Machine-readable revision for Guard synchronization and evidence APIs."""
    return {
        "schema": AUTHORIZATION_REVISION_SCHEMA,
        "application_id": row.application_id,
        "revision": row.revision,
        "revision_hash": row.revision_hash,
        "previous_revision_hash": row.previous_revision_hash,
        "source_id": row.source_id,
        "generated_at": _iso(row.generated_at),
        "source_observed_at": _iso(row.source_observed_at),
        "payload": json.loads(row.payload_json),
        "signature": json.loads(row.signed_manifest_json),
    }


def latest_revision(db: OrmSession, organization_id: str, application_id: str) -> AuthorizationRevision | None:
    return db.scalar(select(AuthorizationRevision).where(
        AuthorizationRevision.organization_id == organization_id,
        AuthorizationRevision.application_id == application_id,
    ).order_by(AuthorizationRevision.revision.desc()).limit(1))


