#!/usr/bin/env python3
"""Operator CLI (runs in the production api container, like the source-certificate import).

    python scripts/remote_route_certificate.py import  --organization-id ORG --application-id APP < cert.json
    python scripts/remote_route_certificate.py attest  --organization-id ORG --application-id APP < attestation.json
    python scripts/remote_route_certificate.py revoke  --organization-id ORG --application-id APP --fingerprint FP
    python scripts/remote_route_certificate.py status  --organization-id ORG --application-id APP
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402

from apps.api.accessproof_api.db import AIApplication, AuditEvent, SessionLocal, set_tenant_context  # noqa: E402
from apps.api.accessproof_api import remote_route_enforcement as rre  # noqa: E402
from apps.api.accessproof_api import gateway_presence  # noqa: E402
from apps.api.accessproof_api.route_certification import describe_route_certificate  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["import", "attest", "revoke", "status"])
    p.add_argument("--organization-id", required=True)
    p.add_argument("--application-id", required=True)
    p.add_argument("--fingerprint")
    a = p.parse_args()
    with SessionLocal() as db:
        set_tenant_context(db, a.organization_id)
        row = db.scalar(select(AIApplication).where(AIApplication.organization_id == a.organization_id,
                                                    AIApplication.application_id == a.application_id,
                                                    AIApplication.archived_at.is_(None)))
        if row is None:
            print(json.dumps({"ok": False, "error": "APPLICATION_NOT_FOUND"}))
            return 2
        try:
            if a.action == "import":
                rec = rre.import_certificate(db, row, json.load(sys.stdin))
                event, detail = "REMOTE_ROUTE_CERTIFICATE_IMPORTED", {"fingerprint": rec.fingerprint, "route_url": rec.route_url}
            elif a.action == "attest":
                rec = rre.apply_attestation(db, row, json.load(sys.stdin))
                event, detail = "REMOTE_ROUTE_ATTESTATION_APPLIED", {"fingerprint": rec.fingerprint, "status": rec.status,
                                                                     "reason": rec.status_reason}
            elif a.action == "revoke":
                rec = rre.revoke(db, row, a.fingerprint or "")
                event, detail = "REMOTE_ROUTE_CERTIFICATE_REVOKED", {"fingerprint": rec.fingerprint}
            else:
                remote = rre.status(db, row)
                app_route = describe_route_certificate(db, row)
                presence = gateway_presence.connectivity(db, row)
                # Only certificate state and authenticated presence metadata:
                # NO installation credential, employee data or signing key.
                # This extends the pre-existing pinned read-only status SSM
                # operation without creating a new IAM permission/document.
                remote["application_route_certificate"] = {
                    "status": app_route["status"],
                    "certified": app_route["certified"],
                    "expires_at": app_route["expires_at"],
                    "scope": app_route["certification_scope"],
                }
                remote["gateway_presence"] = {
                    "connection": presence["connection"],
                    "enforcement_ready_reported": presence["enforcement_ready_reported"],
                    "reason": presence.get("reason"),
                }
                print(json.dumps(remote, indent=1))
                return 0
        except rre.RemoteRouteError as exc:
            db.rollback()
            print(json.dumps({"ok": False, "error": str(exc)}))
            return 1
        db.add(AuditEvent(organization_id=row.organization_id, action=event, target_type="ai_application",
                          target_id=row.id, metadata_json=json.dumps(detail)))
        db.commit()
        print(json.dumps({"ok": True, "event": event, **detail, "status": rre.status(db, row)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
