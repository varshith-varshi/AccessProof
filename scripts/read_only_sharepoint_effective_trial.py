"""Read-only authorized SharePoint effective-access probe; never print credentials."""
import asyncio
import json
import os
import sys
from pathlib import Path

# Support both direct CLI execution and `python -m scripts...`.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx

from connectors.microsoft365.sharepoint_effective import SharePointEffectiveAccessProbe, SharePointPermissionError
from connectors.microsoft365.sharepoint_authorization import diagnose_sharepoint_rest_token
from connectors.microsoft365.graph_employee_identity import GraphEmployeeIdentityResolver, MicrosoftIdentityResolutionError
from packages.auth.microsoft_certificate import sharepoint_rest_app_token, SharePointCertificateAuthError
from packages.auth.microsoft_consent import graph_app_token
from scripts.sharepoint_trial_verdict import validate_synthetic_access

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
        # Revalidate immutable Entra object IDs live before using SharePoint
        # login names. Never take a mutable email from the challenge caller.
        store = HOME / ".config/accessproof/sharepoint-rest-validation/synthetic-verified-employees.json"
        if store.is_symlink() or not store.is_file():
            print("NO_VERIFIED_EMPLOYEE_IDENTITY_BINDING")
            return 2
        saved_users = json.loads(store.read_text())
        with httpx.Client(timeout=15, follow_redirects=False, trust_env=False) as graph_client:
            graph_token, _ = graph_app_token(
                tenant_id=TENANT, client_id=REG["client_id"],
                client_secret=SECRET["client_secret"], client=graph_client,
            )
        resolver = GraphEmployeeIdentityResolver(
            tenant_id=TENANT, graph_access_token=graph_token, client=client,
        )
        if set(saved_users) != {"alice", "bob"}:
            print("LAB_EMPLOYEE_IDENTITY_SET_CHANGED")
            return 2
        permission_failures = 0
        successfully_observed = 0
        observations: dict[tuple[str, int], bool] = {}
        for name in ("alice", "bob"):
            identity = saved_users[name]
            try:
                employee = await resolver.verify_employee(object_id=identity["object_id"])
                if (identity["tenant_id"] != employee.tenant_id
                        or identity["user_principal_name"] != employee.user_principal_name
                        or identity["sharepoint_login_name"] != employee.sharepoint_login_name):
                    raise MicrosoftIdentityResolutionError("GRAPH_EMPLOYEE_BINDING_CHANGED")
            except (KeyError, TypeError, MicrosoftIdentityResolutionError):
                print("EMPLOYEE_IDENTITY_VERIFICATION_FAILED", name)
                return 2
            for item_id in (2, 3, 4):
                try:
                    allow = await probe.can_view_item(
                        list_id=LIST_ID, item_id=item_id, verified_login_name=employee.sharepoint_login_name,
                    )
                    successfully_observed += 1
                    observations[(name, item_id)] = allow
                    print("EFFECTIVE_ACCESS_UNCERTIFIED", name, item_id, allow)
                except SharePointPermissionError as exc:
                    permission_failures += 1
                    print("EFFECTIVE_ACCESS_INCOMPLETE", name, item_id, str(exc))
        print("EFFECTIVE_PERMISSION_RESULTS", successfully_observed, "OF_6",
              "ERRORS", permission_failures)
        print("NOT_CERTIFIED: permission results alone do not establish"
              " employee OIDC, revocation, or Layer 1/2 release proof")
        if permission_failures or successfully_observed != 6:
            return 2
        deviations = validate_synthetic_access(observations)
        for deviation in deviations:
            print("SYNTHETIC_PERMISSION_POLICY_FAILURE", deviation)
        if deviations:
            return 2
        print("SYNTHETIC_PERMISSION_MATRIX_PASSED_READ_ONLY")
    return 0

if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
