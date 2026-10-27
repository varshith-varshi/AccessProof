from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.accessproof_api.config import settings
from apps.api.accessproof_api.db import (
    AlertRecord,
    EmailOutbox,
    Membership,
    User,
    WebhookDelivery,
    WebhookEndpoint,
)
from packages.crypto.secrets import build_secret_backend

_box = build_secret_backend(
    backend=settings.secret_backend,
    local_key=settings.secret_encryption_key,
    aws_kms_key_id=settings.aws_kms_key_id,
    aws_region=settings.aws_region,
)


def queue_alert(
    db: Session,
    *,
    organization_id: str,
    project_id: str | None,
    kind: str,
    severity: str,
    dedupe_key: str,
    subject: str,
    detail: str,
) -> bool:
    if db.scalar(select(AlertRecord.id).where(AlertRecord.dedupe_key == dedupe_key)):
        return False
    alert = AlertRecord(
        organization_id=organization_id,
        project_id=project_id,
        kind=kind,
        severity=severity,
        dedupe_key=dedupe_key,
        subject=subject,
        detail=detail,
    )
    db.add(alert)
    # SessionLocal deliberately disables autoflush. Flush the dedupe record before
    # fan-out so a second alert queued in the same transaction observes it instead
    # of colliding with the unique constraint at commit.
    db.flush()
    admins = (
        db.execute(
            select(User.email)
            .join(Membership, Membership.user_id == User.id)
            .where(
                Membership.organization_id == organization_id,
                Membership.role.in_(["OWNER", "ADMIN"]),
            )
        )
        .scalars()
        .all()
    )
    for email in sorted(set(admins)):
        db.add(
            EmailOutbox(
                organization_id=organization_id,
                recipient=email,
                template="operational_alert",
                subject=subject,
                encrypted_payload=_box.encrypt(json.dumps({"text_body": detail}, sort_keys=True)),
                status="pending",
                attempts=0,
                next_attempt_at=datetime.now(timezone.utc),
            )
        )
    payload = {
        "id": str(uuid4()),
        "type": f"alert.{kind}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "data": {
            "severity": severity,
            "project_id": project_id,
            "subject": subject,
            "detail": detail,
        },
    }
    endpoints = db.scalars(
        select(WebhookEndpoint).where(
            WebhookEndpoint.organization_id == organization_id, WebhookEndpoint.enabled.is_(True)
        )
    )
    for endpoint in endpoints:
        if endpoint.project_id is None or endpoint.project_id == project_id:
            db.add(
                WebhookDelivery(
                    organization_id=organization_id,
                    endpoint_id=endpoint.id,
                    event_type=f"alert.{kind}",
                    payload_json=json.dumps(payload, sort_keys=True),
                )
            )
    return True
