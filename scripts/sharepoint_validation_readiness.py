"""Read-only production SharePoint readiness report.

Run inside the AccessProof API container:
    python -m scripts.sharepoint_validation_readiness --application sharepoint-rag-staging

No credentials, tokens, user identifiers, document content or private source
metadata appear in the output. This never issues a certificate, updates
application mode, grants SharePoint rights or approves customer cutover.
"""
from __future__ import annotations

import argparse
import json
from typing import Any

from sqlalchemy import select

from apps.api.accessproof_api.app import _automatic_activation_checklist
from apps.api.accessproof_api.db import AIApplication, SessionLocal


def summarize_checks(checks: list[dict[str, Any]]) -> dict[str, Any]:
    """Fail closed for absent, duplicate, malformed or negative evidence."""
    if not checks:
        return {
            "readiness": "NO_GO",
            "failed_checks": ["CHECKLIST_UNAVAILABLE"],
            "certificate_verified": False,
            "safe_to_enable_protect": False,
        }
    seen: set[str] = set()
    failed: list[str] = []
    for row in checks:
        if not isinstance(row, dict):
            return {
                "readiness": "NO_GO",
                "failed_checks": ["CHECKLIST_INVALID"],
                "certificate_verified": False,
                "safe_to_enable_protect": False,
            }
        code = row.get("code")
        ok = row.get("ok")
        if not isinstance(code, str) or not code or code in seen or type(ok) is not bool:
            return {
                "readiness": "NO_GO",
                "failed_checks": ["CHECKLIST_INVALID"],
                "certificate_verified": False,
                "safe_to_enable_protect": False,
            }
        seen.add(code)
        if not ok:
            failed.append(code)
    # For this SharePoint release, these are mandatory even if a caller
    # supplies a small or incomplete checklist.
    mandatory = {
        "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED",
        "V1_PROVIDER_SCOPE",
        "PRODUCTION_OIDC_READY",
        "LAYER1_INTEGRATION_CONFIRMED",
        "LAYER2_INTEGRATION_CONFIRMED",
        "PROVENANCE_READY",
        "BUFFERED_RESPONSE_GATE_READY",
        "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED",
        "CUSTOMER_RAG_CUTOVER_NOT_VERIFIED",
    }
    if not mandatory.issubset(seen):
        failed.extend(sorted(mandatory - seen))
    return {
        "readiness": "CHECKS_PASSED_REQUIRES_INDEPENDENT_REVIEW" if not failed else "NO_GO",
        "failed_checks": sorted(set(failed)),
        "certificate_verified": (
            "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED" in seen
            and "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED" not in failed
        ),
        # Never interpret a checklist snapshot as customer approval.
        "safe_to_enable_protect": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only AccessProof production SharePoint readiness")
    parser.add_argument("--application", default="sharepoint-rag-staging",
                        help="Application ID; must resolve to exactly one tenant application")
    args = parser.parse_args()
    try:
        with SessionLocal() as session:
            matches = session.scalars(
                select(AIApplication).where(AIApplication.application_id == args.application).limit(2)
            ).all()
            if len(matches) != 1:
                verdict = summarize_checks([])
                verdict["failed_checks"] = ["APPLICATION_NOT_UNIQUE_OR_NOT_FOUND"]
            else:
                verdict = summarize_checks(_automatic_activation_checklist(session, matches[0]))
                verdict["application_mode"] = matches[0].mode
        verdict["diagnostic_type"] = "READ_ONLY_LOCAL_CONTROL_PLANE"
        print(json.dumps(verdict, sort_keys=True))
        return 0 if verdict["readiness"] == "CHECKS_PASSED_REQUIRES_INDEPENDENT_REVIEW" else 2
    except Exception:
        # Never dump credentials or ORM error strings to stderr.
        print(json.dumps({
            "diagnostic_type": "READ_ONLY_LOCAL_CONTROL_PLANE",
            "readiness": "NO_GO",
            "failed_checks": ["LOCAL_READINESS_QUERY_UNAVAILABLE"],
            "certificate_verified": False,
            "safe_to_enable_protect": False,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
