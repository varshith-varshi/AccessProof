#!/usr/bin/env python3
"""Configure ONLY the synthetic AccessProof SharePoint REST validation app.

Never disables MFA/Security Defaults or grants tenant-wide SharePoint access.
Requires successful interactive Entra admin authentication. No credentials,
private keys, JWTs or Graph response bodies are printed. Dry-run by default.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
from pathlib import Path
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization

SHAREPOINT_API = "00000003-0000-0ff1-ce00-000000000000"
TEST_SITE_ID = (
    "neuralmatrix093.sharepoint.com,"
    "9b00ec42-620a-4efc-acb3-f4d662c8ceb6,"
    "20231c9b-3196-4a5e-9ed0-0404090d5930"
)


def read_json(command: list[str]) -> object:
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError("MICROSOFT_ADMIN_AUTHENTICATION_OR_DIRECTORY_PERMISSION_REQUIRED")
    try:
        return json.loads(completed.stdout)
    except ValueError as exc:
        raise RuntimeError("MICROSOFT_ADMIN_DIRECTORY_RESPONSE_INVALID") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true",
        help="Apply changes only after an authorized tenant admin completed MFA.")
    parser.add_argument("--approve-test-site-fullcontrol", action="store_true",
        help="Explicitly approve FullControl on the ONLY synthetic test site. "
             "Needed if the effective-permission endpoint requires ACL enumeration.")
    args = parser.parse_args()
    home = Path.home() / ".config/accessproof"
    app = json.loads((home / "entra-app-registration.json").read_text())
    tenant, app_id = str(UUID(app["home_tenant"])), str(UUID(app["client_id"]))
    certificate = home / "sharepoint-rest-validation/client-public.pem"
    if not certificate.is_file() or certificate.is_symlink():
        raise RuntimeError("PUBLIC_SHAREPOINT_CERTIFICATE_MISSING")
    print("Scope: one app registration, one synthetic SharePoint site, SharePoint Sites.Selected")
    print("Certificate: PUBLIC certificate only; private key remains on this workstation")
    print("Expected tenant:", tenant)
    print("Target app:", app_id)
    print("Target site:", TEST_SITE_ID)
    if not args.apply:
        print("DRY_RUN_ONLY: no Entra registration, Microsoft permissions, or site ACL changed.")
        print("First complete Entra interactive admin sign-in (including MFA).")
        print("Then rerun --apply; use --approve-test-site-fullcontrol only if authorized.")
        return 0
    account = read_json(["az", "account", "show", "-o", "json"])
    if not isinstance(account, dict) or account.get("tenantId") != tenant:
        raise RuntimeError("ENTRA_SIGNED_IN_TENANT_MISMATCH")
    service_principal = read_json(["az", "ad", "sp", "show", "--id", SHAREPOINT_API, "-o", "json"])
    if not isinstance(service_principal, dict):
        raise RuntimeError("SHAREPOINT_SERVICE_PRINCIPAL_NOT_FOUND")
    roles = [
        role for role in service_principal.get("appRoles", [])
        if isinstance(role, dict)
        and role.get("value") == "Sites.Selected"
        and "Application" in role.get("allowedMemberTypes", [])
        and role.get("isEnabled")
    ]
    if len(roles) != 1:
        raise RuntimeError("SHAREPOINT_SITES_SELECTED_APP_ROLE_NOT_IDENTIFIED")
    role_id = str(UUID(roles[0]["id"]))
    current_app = read_json(["az", "ad", "app", "show", "--id", app_id, "-o", "json"])
    if not isinstance(current_app, dict):
        raise RuntimeError("ENTRA_APPLICATION_NOT_READABLE")
    requested = any(
        entry.get("resourceAppId") == SHAREPOINT_API
        and any(row.get("id") == role_id and row.get("type") == "Role"
                for row in entry.get("resourceAccess", []))
        for entry in current_app.get("requiredResourceAccess", [])
    )
    if not requested:
        # Only the SharePoint Sites.Selected scope, NEVER Sites.FullControl.All.
        subprocess.run([
            "az", "ad", "app", "permission", "add", "--id", app_id,
            "--api", SHAREPOINT_API, "--api-permissions", role_id + "=Role",
            "--only-show-errors",
        ], check=True)
    # The OAuth public thumbprint is SHA-1 of the DER-encoded X509 certificate.
    # This is identification, NOT a cryptographic signature algorithm choice.
    public_cert = x509.load_pem_x509_certificate(certificate.read_bytes())
    public_der = public_cert.public_bytes(serialization.Encoding.DER)
    thumbprint = base64.b64encode(hashlib.sha1(public_der).digest()).decode()
    uploaded = any(
        row.get("customKeyIdentifier") == thumbprint
        for row in current_app.get("keyCredentials", [])
    )
    if not uploaded:
        # --append is critical: never rotate/delete existing client credentials.
        subprocess.run([
            "az", "ad", "app", "credential", "reset", "--id", app_id,
            "--cert", "@" + str(certificate), "--append",
            "--only-show-errors", "--output", "none",
        ], check=True)
    subprocess.run([
        "az", "ad", "app", "permission", "admin-consent", "--id", app_id,
        "--only-show-errors", "--output", "none",
    ], check=True)
    print("Application: SharePoint Sites.Selected consent and public cert registered.")
    print("Checking site grant with administrator identity...")
    site_url = "https://graph.microsoft.com/v1.0/sites/" + TEST_SITE_ID + "/permissions"
    permissions = read_json(["az", "rest", "--method", "get", "--url", site_url, "--output", "json"])
    if not isinstance(permissions, dict):
        raise RuntimeError("MICROSOFT_TEST_SITE_PERMISSION_REVIEW_UNAVAILABLE")
    assignments = [
        row for row in permissions.get("value", [])
        if any(
            identity.get("application", {}).get("id", "").lower() == app_id
            for identity in row.get("grantedToIdentitiesV2", row.get("grantedToIdentities", []))
        )
    ]
    if assignments and any("fullcontrol" in x.get("roles", []) for x in assignments):
        print("Synthetic site already grants app FullControl; no grant changed.")
        return 0
    if not args.approve_test_site_fullcontrol:
        print("SITE_FULLCONTROL_NOT_APPROVED: No site permission was changed.")
        print("ACL inspection may need site-scoped FullControl. Obtain approval "
              "before setting --approve-test-site-fullcontrol.")
        return 2
    if assignments:
        print("EXISTING_SITE_GRANT_REQUIRES_REVIEW: refusing duplicate or silent upgrade.")
        return 2
    # The grant is limited to ONE named synthetic test site; no tenant-wide grant.
    body = json.dumps({
        "roles": ["fullcontrol"],
        "grantedToIdentities": [{"application": {
            "id": app_id, "displayName": app.get("name", "AccessProof synthetic test"),
        }}],
    })
    subprocess.run([
        "az", "rest", "--method", "post", "--url", site_url,
        "--headers", "Content-Type=application/json", "--body", body,
        "--output", "none",
    ], check=True)
    print("Synthetic test site only: FullControl assigned for effective-ACL verification.")
    print("Next: run certificate probe. This is NOT Protect certification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
