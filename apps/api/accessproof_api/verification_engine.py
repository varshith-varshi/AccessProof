"""Durable, fail-closed verification coordination.

The worker evaluates independent *existing* proof gates, it does not create
provider certificates, employee logins, route attestations, or Protect claims.
Work is durable in PostgreSQL, not dependent on Redis delivery.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from apps.api.accessproof_api.db import (
    AIApplication, GuardRegistration, Organization, SessionLocal, SourceConnection,
    VerificationApproval, VerificationEvent, VerificationOutbox, VerificationRun, VerificationStep,
    set_tenant_context,
)
from apps.api.accessproof_api import gateway_pairing

ADMIN_CODES = frozenset({
    "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED", "V1_PROVIDER_SCOPE",
    "PRODUCTION_OIDC_READY",
})
CHALLENGE_CODES = frozenset({
    "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED", "LAYER1_INTEGRATION_CONFIRMED",
    "LAYER2_INTEGRATION_CONFIRMED", "PROVENANCE_READY", "BUFFERED_RESPONSE_GATE_READY",
})
CUTOVER_CODES = frozenset({"CUSTOMER_RAG_CUTOVER_NOT_VERIFIED"})
TRANSIENT_CODES = frozenset({
    "GUARD_HEARTBEAT_RECENT", "GUARD_POLICY_INSTALLED", "PERMISSION_SOURCE_SYNCED",
    "PERMISSION_DIRECTORY_SYNCED", "PERMISSION_SOURCE_USABLE",
    "PERMISSION_SOURCE_TRUSTED", "PERMISSION_EVENTS_RESOLVED",
})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _fingerprint(row: AIApplication, deployment: str, route: str, policy: int, source: SourceConnection | None) -> str:
    # Critical inputs are server-side bindings, not caller-controlled org IDs.
    value = json.dumps({
        "org": row.organization_id, "application": row.id, "source": row.source_id,
        "guard": row.guard_id, "policy": policy,
        "provider": source.provider if source else None,
        "boundary": source.boundary if source else None,
        "deployment": deployment, "route": route,
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(value.encode()).hexdigest()


def _event(db: Session, run: VerificationRun, code: str, state: str, reason: str | None = None) -> None:
    db.add(VerificationEvent(
        organization_id=run.organization_id, run_id=run.id, code=code,
        state=state, detail=(reason or "")[:400] or None,
    ))


def start_or_resume(db: Session, row: AIApplication, *, deployment: str, route: str) -> VerificationRun:
    """Idempotent write called only after a validated one-use installation claim."""
    if len(deployment) != 64 or len(route) != 64 or not row.guard_id or not row.source_id:
        raise ValueError("VERIFICATION_INSTALLATION_SCOPE_REQUIRED")
    guard = db.get(GuardRegistration, row.guard_id)
    source = db.get(SourceConnection, row.source_id)
    if not guard or not source or guard.organization_id != row.organization_id or source.organization_id != row.organization_id:
        raise ValueError("VERIFICATION_BINDING_INVALID")
    fp = _fingerprint(row, deployment, route, guard.active_policy_version, source)
    existing = db.scalar(select(VerificationRun).where(
        VerificationRun.organization_id == row.organization_id,
        VerificationRun.application_row_id == row.id,
        VerificationRun.fingerprint == fp,
    ))
    if existing:
        return existing
    # A changed route/Guard/source/policy must invalidate older workflow state.
    for previous in db.scalars(select(VerificationRun).where(
        VerificationRun.organization_id == row.organization_id,
        VerificationRun.application_row_id == row.id,
        VerificationRun.superseded_at.is_(None),
    )):
        previous.superseded_at = _now()
        previous.state = "SUPERSEDED"
        _event(db, previous, "RUN", "SUPERSEDED", "Deployment or security binding changed.")
    run = VerificationRun(
        organization_id=row.organization_id, application_row_id=row.id, guard_id=guard.id,
        source_id=source.id, deployment_sha256=deployment, route_sha256=route,
        fingerprint=fp, state="QUEUED", next_check_at=_now(),
    )
    db.add(run)
    db.flush()
    _event(db, run, "RUN", "QUEUED", "Verified pairing started automatic assessment.")
    db.add(VerificationOutbox(organization_id=run.organization_id, run_id=run.id,
                              generation=run.generation, state="PENDING",
                              available_at=_now(), attempts=0))
    return run


def safe_step_state(code: str, ok: bool) -> str:
    if ok:
        return "SATISFIED"
    if code in ADMIN_CODES:
        return "WAITING_FOR_ADMIN"
    if code in CUTOVER_CODES:
        return "WAITING_FOR_CUTOVER"
    if code in CHALLENGE_CODES:
        return "WAITING_FOR_CHALLENGE"
    if code in TRANSIENT_CODES:
        return "RETRY_SCHEDULED"
    return "BLOCKED"


def reconcile_checks(db: Session, run: VerificationRun, checks: list[dict[str, Any]]) -> None:
    """Read existing authoritative evidence and persist states; never create certificates."""
    if not checks or any(
        not isinstance(c, dict) or not isinstance(c.get("code"), str) or type(c.get("ok")) is not bool
        for c in checks
    ):
        raise ValueError("VERIFICATION_CHECKLIST_INVALID")
    codes = [str(c["code"]) for c in checks]
    if len(codes) != len(set(codes)):
        raise ValueError("VERIFICATION_CHECKLIST_DUPLICATED")
    now = _now()
    known = {v.code: v for v in db.scalars(select(VerificationStep).where(
        VerificationStep.organization_id == run.organization_id, VerificationStep.run_id == run.id,
    ))}
    failed: set[str] = set()
    for check in checks:
        code = str(check["code"])
        ok = check["ok"]
        reason = None if ok else str(check.get("reason") or "Independent evidence required.")[:400]
        state = safe_step_state(code, ok)
        if not ok:
            failed.add(code)
        step = known.get(code)
        if step is None:
            step = VerificationStep(organization_id=run.organization_id, run_id=run.id,
                                    code=code, state="PENDING", attempt=0)
            db.add(step)
        if step.state != state:
            _event(db, run, code, state, reason)
        step.state, step.reason, step.checked_at = state, reason, now
        # A passing checklist predicate does not constitute evidence issuance.
        step.evidence_id = None
        if state == "RETRY_SCHEDULED":
            step.attempt = min(step.attempt + 1, 20)
            step.next_retry_at = now + timedelta(seconds=min(300, 5 * 2 ** min(step.attempt, 5)))
        else:
            step.attempt = 0
            step.next_retry_at = None
    for code, step in known.items():
        if code not in set(codes):
            step.state, step.reason, step.checked_at = "STALE", "Check disappeared from authoritative checklist.", now
            failed.add(code)
            _event(db, run, code, "STALE", step.reason)
    if not failed:
        new_state = "CHECKS_PASSED_REQUIRES_INDEPENDENT_REVIEW"
    elif failed & ADMIN_CODES:
        new_state = "WAITING_FOR_AUTHORIZATION"
    elif failed & CHALLENGE_CODES:
        new_state = "WAITING_FOR_CHALLENGE"
    elif failed & CUTOVER_CODES:
        new_state = "WAITING_FOR_CUTOVER"
    elif failed <= TRANSIENT_CODES:
        new_state = "RETRY_SCHEDULED"
    else:
        new_state = "BLOCKED"
    if run.state != new_state:
        _event(db, run, "RUN", new_state)
    run.state = new_state
    run.updated_at = now
    # Retries use the database outbox, not a best-effort Redis message.
    run.next_check_at = now + timedelta(seconds=30 if new_state == "RETRY_SCHEDULED" else 60)


def describe(db: Session, run: VerificationRun) -> dict[str, Any]:
    steps = list(db.scalars(select(VerificationStep).where(
        VerificationStep.organization_id == run.organization_id, VerificationStep.run_id == run.id,
    ).order_by(VerificationStep.code)))
    good = sum(step.state == "SATISFIED" for step in steps)
    return {
        "run_id": run.id, "state": run.state, "generation": run.generation,
        "created_at": run.created_at.isoformat(), "updated_at": run.updated_at.isoformat(),
        "deployment_sha256": run.deployment_sha256, "route_sha256": run.route_sha256,
        "scope_fingerprint": run.fingerprint,
        "checks_passed": good, "checks_total": len(steps),
        "protect_activated": False, "production_certification": False,
        "steps": [{"code": s.code, "state": s.state, "reason": s.reason,
                   "attempt": s.attempt, "next_retry_at": s.next_retry_at.isoformat() if s.next_retry_at else None,
                   "checked_at": s.checked_at.isoformat() if s.checked_at else None,
                   "evidence_ref": None} for s in steps],
    }


def record_scoped_approval(
    db: Session, run: VerificationRun, *, actor_id: str,
    approval_type: str, acknowledged_fingerprint: str,
) -> VerificationApproval:
    """Explicit owner approval for a fixed deployment, never Microsoft consent.

    This only records authorization. It NEVER runs a challenge, changes ACLs,
    activates Protect, changes routing, or issues a provider certificate.
    """
    if approval_type not in {"SYNTHETIC_TEST_SCOPE", "CUSTOMER_ROUTE_CUTOVER"}:
        raise ValueError("UNSUPPORTED_APPROVAL_TYPE")
    if run.superseded_at is not None or acknowledged_fingerprint != run.fingerprint:
        raise ValueError("APPROVAL_DEPLOYMENT_FINGERPRINT_MISMATCH")
    # A route approval cannot be accepted before the operator has a real
    # challenge result. It does not substitute for verifying that route.
    if approval_type == "CUSTOMER_ROUTE_CUTOVER":
        challenge = db.scalar(select(VerificationStep).where(
            VerificationStep.run_id == run.id,
            VerificationStep.organization_id == run.organization_id,
            VerificationStep.code == "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED",
            VerificationStep.state == "SATISFIED",
        ))
        if challenge is None:
            raise ValueError("CUSTOMER_ROUTE_CHALLENGE_REQUIRED_BEFORE_APPROVAL")
    existing = db.scalar(select(VerificationApproval).where(
        VerificationApproval.organization_id == run.organization_id,
        VerificationApproval.run_id == run.id,
        VerificationApproval.approval_type == approval_type,
        VerificationApproval.generation == run.generation,
    ))
    if existing:
        if _aware(existing.expires_at) <= _now() or existing.consumed_at is not None:
            raise ValueError("APPROVAL_EXPIRED_OR_CONSUMED")
        return existing
    approval = VerificationApproval(
        organization_id=run.organization_id, run_id=run.id,
        approval_type=approval_type, generation=run.generation,
        actor_id=actor_id, scope_digest=run.fingerprint,
        approved_at=_now(), expires_at=_now() + timedelta(hours=1),
    )
    db.add(approval)
    _event(db, run, approval_type, "OWNER_APPROVED_PENDING_INDEPENDENT_VERIFICATION")
    return approval


def newest_run(db: Session, row: AIApplication) -> VerificationRun | None:
    return db.scalar(select(VerificationRun).where(
        VerificationRun.organization_id == row.organization_id,
        VerificationRun.application_row_id == row.id,
        VerificationRun.superseded_at.is_(None),
    ).order_by(VerificationRun.created_at.desc()).limit(1))


def run_worker_cycle(max_runs: int = 12) -> int:
    """Bounded database-owned work; one worker per run via row locks.

    Reconciles Redis pairing gaps after the machine claim is accepted but the
    API crashes before committing the verification row.
    """
    from apps.api.accessproof_api.app import _automatic_activation_checklist
    processed = 0
    with SessionLocal() as organizations_db:
        org_ids = list(organizations_db.scalars(select(Organization.id)))
    for org_id in org_ids:
        if processed >= max_runs:
            break
        with SessionLocal() as db:
            set_tenant_context(db, org_id)
            # Bound reconciliation, same-tenant only. Redis outages do not
            # erase any existing durable runs/outbox tasks.
            for app in db.scalars(select(AIApplication).where(
                AIApplication.organization_id == org_id,
                AIApplication.adapter_type == "accessproof-gateway",
            ).limit(50)):
                try:
                    pairing = gateway_pairing.status(org_id=org_id, app_row_id=app.id)
                    if pairing.get("state") == "installation_reported_unverified":
                        deployment, route = pairing.get("deployment_sha256"), pairing.get("route_sha256")
                        if isinstance(deployment, str) and isinstance(route, str):
                            start_or_resume(db, app, deployment=deployment, route=route)
                            db.commit()
                except (gateway_pairing.PairingError, ConnectionError):
                    db.rollback()
                except IntegrityError:
                    db.rollback()
            now = _now()
            pending = list(db.scalars(select(VerificationOutbox).join(
                VerificationRun, VerificationRun.id == VerificationOutbox.run_id
            ).where(
                VerificationOutbox.organization_id == org_id,
                VerificationRun.superseded_at.is_(None),
                VerificationOutbox.available_at <= now,
            ).order_by(VerificationOutbox.available_at).with_for_update(skip_locked=True).limit(max_runs - processed)))
            for job in pending:
                run = db.get(VerificationRun, job.run_id)
                target_app = db.get(AIApplication, run.application_row_id) if run else None
                if not run or not target_app or run.superseded_at or target_app.organization_id != org_id:
                    job.state = "CANCELLED"
                    job.available_at = now + timedelta(days=365)
                    continue
                try:
                    checks = _automatic_activation_checklist(db, target_app)
                    reconcile_checks(db, run, checks)
                    job.state = "WAITING_NEXT_CHECK"
                    job.available_at = run.next_check_at
                    job.attempts = 0
                    db.commit()
                    processed += 1
                except Exception:
                    db.rollback()
                    retry_job = db.get(VerificationOutbox, job.id)
                    if retry_job is None:
                        continue
                    retry_job.attempts = min(retry_job.attempts + 1, 20)
                    retry_job.state = "RETRY_SCHEDULED"
                    retry_job.available_at = _now() + timedelta(
                        seconds=min(300, 5 * 2 ** min(retry_job.attempts, 6)))
                    db.commit()
    return processed
