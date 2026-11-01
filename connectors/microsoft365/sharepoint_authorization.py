"""Non-authoritative OAuth scope diagnostics for SharePoint REST API.

Decoding claims is for operator troubleshooting only. JWT signatures are NOT
verified here; this module never makes an ALLOW, CERTIFY, or Protect decision.
"""
from __future__ import annotations

import base64
import json
from uuid import UUID

SHAREPOINT_RESOURCE_AUDIENCE = "00000003-0000-0ff1-ce00-000000000000"
REQUIRED_SHAREPOINT_APP_ROLE = "Sites.Selected"


def diagnose_sharepoint_rest_token(
    token: str,
    *,
    tenant_id: str,
    application_id: str,
) -> list[str]:
    """Return failure codes, never raw token, user identity, or claim contents."""
    try:
        if not isinstance(token, str) or len(token) > 16000:
            return ["SHAREPOINT_JWT_UNREADABLE"]
        parts = token.split(".")
        if len(parts) != 3 or not (20 <= len(parts[1]) <= 12000):
            return ["SHAREPOINT_JWT_UNREADABLE"]
        parsed = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        if not isinstance(parsed, dict):
            return ["SHAREPOINT_JWT_UNREADABLE"]
        expected_tenant = str(UUID(tenant_id))
        expected_app = str(UUID(application_id))
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return ["SHAREPOINT_JWT_UNREADABLE"]
    errors: list[str] = []
    if parsed.get("aud") != SHAREPOINT_RESOURCE_AUDIENCE:
        errors.append("SHAREPOINT_TOKEN_WRONG_AUDIENCE")
    if parsed.get("tid") != expected_tenant:
        errors.append("SHAREPOINT_TOKEN_WRONG_TENANT")
    if parsed.get("appid", parsed.get("azp")) != expected_app:
        errors.append("SHAREPOINT_TOKEN_WRONG_APPLICATION")
    roles = parsed.get("roles")
    if not isinstance(roles, list) or REQUIRED_SHAREPOINT_APP_ROLE not in roles:
        errors.append("SHAREPOINT_REST_SITES_SELECTED_APP_ROLE_MISSING")
    if parsed.get("appidacr") != "2":
        errors.append("SHAREPOINT_APP_ONLY_CERTIFICATE_REQUIRED")
    return errors
