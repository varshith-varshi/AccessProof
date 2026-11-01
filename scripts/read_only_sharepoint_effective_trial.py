"""Read-only authorized SharePoint effective-access probe; never print credentials."""
import asyncio
import json
import os
from pathlib import Path

import httpx

from connectors.microsoft365.sharepoint_effective import SharePointEffectiveAccessProbe, SharePointPermissionError
from connectors.microsoft365.sharepoint_authorization import diagnose_sharepoint_rest_token
from packages.auth.microsoft_certificate import sharepoint_rest_app_token, SharePointCertificateAuthError

HOME = Path.home()
REG = json.loads((HOME / ".config/accessproof/entra-app-registration.json").read_text())
SECRET = json.loads((HOME / ".config/accessproof/entra-client-secret.json").read_text())
TENANT = REG["home_tenant"]
SITE_URL = "https://neuralmatrix093.sharepoint.com/sites/AccessProof-Validation-20261027"
LIST_ID = "8200ffae-ba10-42c5-bfa9-8f7ac155c5c4"

async def run() -> int:
    async with httpx.AsyncClient(timeout=18, trust_env=False, follow_redirects=False) as client:
        certificate_mode = os.getenv("ACCESSPROOF_SHAREPOINT_CERTIFICATE_PROBE") == "1"
        if certificate_mode:
            private_dir = HOME / ".config/accessproof/sharepoint-rest-validation"
            try:
                token = await sharepoint_rest_app_token(
                    tenant_id=TENANT,
                    client_id=REG["client_id"],
                    sharepoint_host="neuralmatrix093.sharepoint.com",
                    private_key_file=private_dir / "client-private.pem",
                    certificate_der_file=private_dir / "client-public.cer",
                    client=client,
                )
                print("SHAREPOINT_CERTIFICATE_TOKEN_HTTP", 200)
            except SharePointCertificateAuthError as exc:
                print("SHAREPOINT_CERTIFICATE_AUTH_BLOCKED", str(exc))
                print("REMEDIATION: Upload the public .cer certificate to the approved "
                      "Entra app registration, grant SharePoint Sites.Selected app "
                      "role with admin consent, and verify the approved site grant.")
                return 2
        else:
            r = await client.post(
                f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
                data={
                    "client_id": REG["client_id"],
                    "client_secret": SECRET["client_secret"],
                    "grant_type": "client_credentials",
                    "scope": "https://neuralmatrix093.sharepoint.com/.default",
                },
            )
            print("SHAREPOINT_AUDIENCE_TOKEN_HTTP", r.status_code)
            if r.status_code != 200:
                print("EFFECTIVE_ACCESS_CANNOT_BE_CERTIFIED: SharePoint API resource scope or consent unavailable")
                return 2
            token = r.json().get("access_token")
            if not isinstance(token, str) or not token:
                print("SHAREPOINT_CERTIFICATE_AUTH_BLOCKED: No usable token")
                return 2
        import base64
        token_part = token.split(".")[1] if isinstance(token, str) and "." in token else ""
        claims = json.loads(base64.urlsafe_b64decode(token_part + "=" * (-len(token_part) % 4))) if token_part else {}
        print("SHAREPOINT_AUTHORIZATION_CLAIMS", {
            "aud": claims.get("aud"), "roles": claims.get("roles", []),
            "scp": claims.get("scp"), "tid": claims.get("tid"),
            "appidacr": claims.get("appidacr"),
        })
        issues = diagnose_sharepoint_rest_token(
            token, tenant_id=TENANT, application_id=REG["client_id"],
        )
        if issues:
            for issue in issues:
                print("SHAREPOINT_REST_AUTHORIZATION_MISSING", issue)
            print("REMEDIATION: Microsoft Entra app registration > API permissions > "
                  "SharePoint > Application permissions > Sites.Selected; "
                  "grant tenant admin consent, upload an app certificate, "
                  "and verify the approved site grant.")
            print("NO_PROTECT_CERTIFICATE_ISSUED")
            return 2
        probe_web = await client.get(SITE_URL + "/_api/web",
            headers={"Authorization": "Bearer " + token, "Accept": "application/json;odata=nometadata"})
        print("SHAREPOINT_REST_WEB_HTTP", probe_web.status_code)
        print("SHAREPOINT_REST_WWW_AUTH_SCHEME", (probe_web.headers.get("WWW-Authenticate") or "")[:190])
        if not token:
            print("EFFECTIVE_ACCESS_CANNOT_BE_CERTIFIED: No SharePoint audience access token")
            return 2
        probe = SharePointEffectiveAccessProbe(site_url=SITE_URL, sharepoint_access_token=token, client=client)
        for name, login in (
            ("alice", "i:0#.f|membership|alice@neuralmatrix093.onmicrosoft.com"),
            ("bob", "i:0#.f|membership|bob@neuralmatrix093.onmicrosoft.com"),
        ):
            for item_id in (2, 3, 4):
                try:
                    allow = await probe.can_view_item(
                        list_id=LIST_ID, item_id=item_id, verified_login_name=login,
                    )
                    print("EFFECTIVE_ACCESS_UNCERTIFIED", name, item_id, allow)
                except SharePointPermissionError as exc:
                    print("EFFECTIVE_ACCESS_INCOMPLETE", name, item_id, str(exc))
        print("NOT_CERTIFIED: login names and employee identity still need independent Entra binding")
    return 0

if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
