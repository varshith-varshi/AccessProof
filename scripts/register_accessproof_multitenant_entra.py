#!/usr/bin/env python3
"""Create the one operator-owned Microsoft Entra application for AccessProof.

Safe defaults: printing the proposed manifest requires no Azure login.
--apply explicitly creates a multitenant app. --create-secret is separately
opt-in, and stores its short-lived value locally with mode 0600, never stdout.
Requires: Azure CLI logged in to the app-owner/home tenant with permission to
create applications. Does NOT grant consent in customer tenants or site access.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
from urllib import error, request
from uuid import UUID

GRAPH_URL = "https://graph.microsoft.com/v1.0"
GRAPH_RESOURCE_ID = "00000003-0000-0000-c000-000000000000"
CALLBACK = "https://api.accessproof.in/api/v1/current/sources/microsoft-admin-consent/callback"
PERMISSIONS = {
    "Sites.Selected": "883ea226-0bf2-4a8f-9f9d-92c9162a727d",
    "User.Read.All": "df021288-bdef-4463-88db-98f22de89214",
    "Group.Read.All": "5b567255-7703-4780-807c-7be8301ae99b",
}

def manifest(name: str = "AccessProof") -> dict[str, object]:
    """No tenant-wide SharePoint read/write permission is requested."""
    return {
        "displayName": name,
        "signInAudience": "AzureADMultipleOrgs",
        "web": {"redirectUris": [CALLBACK]},
        "requiredResourceAccess": [{
            "resourceAppId": GRAPH_RESOURCE_ID,
            "resourceAccess": [
                {"id": permission_id, "type": "Role"}
                for permission_id in PERMISSIONS.values()
            ],
        }],
    }

def _login() -> tuple[str, str]:
    try:
        tenant = subprocess.check_output(
            ["az", "account", "show", "--query", "tenantId", "-o", "tsv"],
            text=True, stderr=subprocess.DEVNULL, timeout=15,
        ).strip()
        token = subprocess.check_output(
            ["az", "account", "get-access-token", "--resource-type", "ms-graph",
             "--query", "accessToken", "-o", "tsv"],
            text=True, stderr=subprocess.DEVNULL, timeout=30,
        ).strip()
        UUID(tenant)
        if not token:
            raise ValueError("Missing Microsoft Graph token")
        return tenant, token
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise RuntimeError(
            "Azure CLI is not authenticated for the app home tenant. "
            "Install Azure CLI, run 'az login --tenant <home-tenant-guid>', "
            "and use an account authorized to register multitenant apps."
        ) from exc

def _graph(token: str, method: str, path: str, payload: dict | None = None) -> dict:
    if not path.startswith("/") or "//" in path or "://" in path:
        raise ValueError("Graph path must be relative")
    data = json.dumps(payload).encode() if payload is not None else None
    req = request.Request(
        GRAPH_URL + path, data=data, method=method,
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with request.urlopen(req, timeout=20) as resp:
            return json.load(resp)
    except error.HTTPError as exc:
        # Never include provider error bodies or access tokens in logs.
        raise RuntimeError(f"Microsoft Graph app-management request failed: HTTP {exc.code}") from exc

def _save(path: Path, payload: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--name", default="AccessProof")
    p.add_argument("--apply", action="store_true",
                   help="Create the operator-owned Entra app using current az CLI login")
    p.add_argument("--create-secret", action="store_true",
                   help="Create a 90-day secret and save it 0600; requires --apply")
    p.add_argument("--output-dir", type=Path,
                   default=Path.home() / ".config" / "accessproof")
    args = p.parse_args()
    if args.create_secret and not args.apply:
        p.error("--create-secret requires --apply")
    definition = manifest(args.name)
    if not args.apply:
        print(json.dumps({"dry_run": True, "registration": definition}, indent=2))
        print("NO MICROSOFT APPLICATION HAS BEEN CREATED")
        return

    home_tenant, token = _login()
    # A duplicate display name could indicate a previous app or a different
    # owner. Never alter/reuse one without an explicit review.
    escaped = args.name.replace("'", "''")
    from urllib.parse import quote
    query = quote(f"displayName eq '{escaped}'")
    existing = _graph(token, "GET", "/applications?$filter=" + query + "&$select=id,appId,displayName")
    if existing.get("value"):
        raise RuntimeError("App name already exists in the home tenant. Review it in Entra; no changes made.")

    created = _graph(token, "POST", "/applications", definition)
    object_id, app_id = created.get("id"), created.get("appId")
    if not object_id or not app_id:
        raise RuntimeError("Graph did not return an app ID; inspect your Entra portal")
    # Never overwrite an existing application record or secret store file.
    _save(args.output_dir / "entra-app-registration.json", {
        "name": args.name, "home_tenant": home_tenant,
        "client_id": app_id, "object_id": object_id,
        "audience": "AzureADMultipleOrgs", "redirect_uri": CALLBACK,
        "graph_application_roles": list(PERMISSIONS),
    })
    if args.create_secret:
        created_secret = _graph(token, "POST", f"/applications/{object_id}/addPassword", {
            "passwordCredential": {
                "displayName": "AccessProof operator service - rotate before expiry",
                "endDateTime": (
                    datetime.now(timezone.utc) + timedelta(days=90)
                ).isoformat().replace("+00:00", "Z"),
            }
        })
        # Service credentials expire after 90 days. The operator must rotate
        # them before expiry; the response metadata is never printed.
        secret = created_secret.get("secretText")
        if not secret:
            raise RuntimeError("App created, but Microsoft returned no secret value")
        _save(args.output_dir / "entra-client-secret.json", {
            "client_id": app_id, "client_secret": secret,
            "expires_at": created_secret.get("endDateTime"),
        })
    print("MULTITENANT ENTRA APP CREATED; home tenant and app ID saved to:")
    print(str(args.output_dir / "entra-app-registration.json"))
    if args.create_secret:
        print("Service secret securely saved to a separate 0600 file; not printed.")
    print("Each customer must still grant tenant admin consent and selected SharePoint site permissions.")

if __name__ == "__main__":
    main()
