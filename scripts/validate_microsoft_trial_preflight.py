#!/usr/bin/env python3
"""Read-only real Microsoft 365 / SharePoint readiness check.

This is NOT Protect certification or a revocation/RAG test. No writes, uploads,
permission mutations, credentials in argv, or token output. Reads only the
explicitly approved drive root and its bounded immediate metadata.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import httpx

from connectors.microsoft365.adapter import Microsoft365Adapter
from packages.auth.microsoft_consent import MicrosoftConsentError, graph_app_token, tenant_uuid
from packages.connector_sdk.base import ConnectorError


@dataclass(frozen=True)
class MicrosoftTrialConfig:
    tenant_id: str
    site_id: str
    list_id: str
    drive_id: str
    root_id: str
    client_id: str
    client_secret: str

    @classmethod
    def from_environment(cls) -> "MicrosoftTrialConfig":
        return cls(
            tenant_id=os.getenv("ACCESSPROOF_MICROSOFT_TENANT_ID", "").strip(),
            site_id=os.getenv("ACCESSPROOF_SHAREPOINT_SITE_ID", "").strip(),
            list_id=os.getenv("ACCESSPROOF_SHAREPOINT_LIST_ID", "").strip(),
            drive_id=os.getenv("ACCESSPROOF_SHAREPOINT_DRIVE_ID", "").strip(),
            root_id=os.getenv("ACCESSPROOF_SHAREPOINT_ROOT_ITEM_ID", "").strip(),
            client_id=os.getenv("ACCESSPROOF_MICROSOFT_CLIENT_ID", "").strip(),
            client_secret=os.getenv("ACCESSPROOF_MICROSOFT_CLIENT_SECRET", "").strip(),
        )


def config_issues(config: MicrosoftTrialConfig) -> list[str]:
    fields = (
        ("ACCESSPROOF_MICROSOFT_TENANT_ID", config.tenant_id),
        ("ACCESSPROOF_SHAREPOINT_SITE_ID", config.site_id),
        ("ACCESSPROOF_SHAREPOINT_LIST_ID", config.list_id),
        ("ACCESSPROOF_SHAREPOINT_DRIVE_ID", config.drive_id),
        ("ACCESSPROOF_SHAREPOINT_ROOT_ITEM_ID", config.root_id),
        ("ACCESSPROOF_MICROSOFT_CLIENT_ID", config.client_id),
        ("ACCESSPROOF_MICROSOFT_CLIENT_SECRET", config.client_secret),
    )
    problems = [f"missing:{key}" for key, val in fields if not val]
    if problems:
        return problems
    try:
        tenant_uuid(config.tenant_id)
        # A Graph site identifier consists of hostname, SPSite GUID, SPWeb GUID.
        host, site_guid, web_guid = config.site_id.split(",")
        if (not host.endswith(".sharepoint.com") or host.startswith(".")
                or host.count(",") or any(char in host for char in "/:@\\?#%")
                or not UUID(site_guid) or not UUID(web_guid)):
            raise ValueError("invalid SharePoint site hostname")
        UUID(config.list_id)
    except (MicrosoftConsentError, ValueError, TypeError):
        problems.append("invalid:tenant_site_or_list_id")
    for key, value in (("drive_id", config.drive_id), ("root_id", config.root_id)):
        if (not value.isascii() or not value or len(value) > 512
                or any(char in value for char in "/?\\#%")
                or any(ord(char) < 32 for char in value)):
            problems.append(f"invalid:{key}")
    return problems


def provider_error(exc: Exception) -> str:
    # Do not return provider response bodies, URLs, tokens, or authorization
    # headers: their contents can include personal and tenant information.
    if isinstance(exc, httpx.HTTPStatusError):
        response = exc.response
        if response.status_code == 400:
            try:
                body = response.json()
                message = (body.get("error") or {}).get("message", "")
            except (ValueError, AttributeError):
                message = ""
            if isinstance(message, str) and "tenant does not have a spo license" in message.lower():
                return "BLOCKED_SHAREPOINT_LICENSE_OR_PROVISIONING"
            return "GRAPH_BAD_REQUEST"
        return f"GRAPH_HTTP_{response.status_code}"
    if isinstance(exc, MicrosoftConsentError):
        return "BLOCKED_APP_REGISTRATION_OR_CONSENT"
    if isinstance(exc, ConnectorError):
        if str(exc) == "MICROSOFT_SHAREPOINT_SERVICE_NOT_READY":
            return "BLOCKED_SHAREPOINT_LICENSE_OR_PROVISIONING"
        return "BLOCKED_GRAPH_SCOPE_OR_SOURCE_BOUNDARY"
    if isinstance(exc, httpx.HTTPError):
        return "GRAPH_TRANSPORT_UNAVAILABLE"
    return "VALIDATION_ERROR"


async def validate(config: MicrosoftTrialConfig) -> dict[str, Any]:
    issues = config_issues(config)
    if issues:
        return {
            "result": "NOT_RUN",
            "reason": "CONFIGURATION_MISSING_OR_INVALID",
            "prerequisites": issues,
            "sharepoint_protect": "NOT_CERTIFIED",
        }
    adapter: Microsoft365Adapter | None = None
    try:
        # Acquire app-only Graph credentials using a trusted tenant endpoint.
        # The existing adapter validates root, site, and library identity.
        access_token, expiry = await asyncio.to_thread(
            graph_app_token,
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret,
        )
        adapter = Microsoft365Adapter(
            access_token=access_token,
            tenant_hint=config.tenant_id,
            drive_id=config.drive_id,
            test_root_item_id=config.root_id,
            sharepoint_site_id=config.site_id,
            sharepoint_list_id=config.list_id,
        )
        await adapter.validate_connection()
        # Read-only and capped to avoid touching unrelated document content.
        resources = await adapter.list_boundary_resources(max_resources=200)
        files = sum(isinstance(item.get("file"), dict) for item in resources)
        return {
            "result": "CONNECTED_READ_ONLY",
            "identity": "TENANT_SCOPED_APP_TOKEN",
            "boundary": "MATCHED_APPROVED_SHAREPOINT_SITE_LIBRARY_AND_FOLDER",
            "resource_metadata_count": len(resources),
            "file_metadata_count": files,
            "token_expiry_valid": isinstance(expiry, datetime),
            "employee_delegated_access": "NOT_TESTED",
            "permission_revocation": "NOT_TESTED",
            "rag_gateway_layer_1_and_2": "NOT_TESTED",
            "cache_reauthorization": "NOT_TESTED",
            "sharepoint_protect": "NOT_CERTIFIED",
        }
    except Exception as exc:
        return {
            "result": "BLOCKED",
            "reason": provider_error(exc),
            "sharepoint_protect": "NOT_CERTIFIED",
        }
    finally:
        if adapter is not None:
            await adapter._client.aclose()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Opt in to read-only Microsoft Graph API calls")
    args = parser.parse_args()
    cfg = MicrosoftTrialConfig.from_environment()
    if not args.live:
        issues = config_issues(cfg)
        outcome: dict[str, Any] = {
            "result": "READY_FOR_LIVE_PREFLIGHT" if not issues else "NOT_RUN",
            "reason": "LIVE_FLAG_REQUIRED" if not issues else "CONFIGURATION_MISSING_OR_INVALID",
            "prerequisites": issues,
            "sharepoint_protect": "NOT_CERTIFIED",
        }
    else:
        outcome = asyncio.run(validate(cfg))
    print(json.dumps(outcome, sort_keys=True))
    return 0 if outcome["result"] in {"READY_FOR_LIVE_PREFLIGHT", "CONNECTED_READ_ONLY"} else 1


if __name__ == "__main__":
    sys.exit(main())
