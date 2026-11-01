"""Read-only immutable Microsoft Graph identity validation for synthetic employees.

Does not authenticate employees, bypass tenant MFA, issue certificates, or
change SharePoint grants. Tokens and secrets never leave process memory.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

import httpx

from connectors.microsoft365.graph_employee_identity import (
    GraphEmployeeIdentityResolver,
    MicrosoftIdentityResolutionError,
)
from packages.auth.microsoft_consent import graph_app_token

ROOT = Path.home() / ".config/accessproof"
TEST_USERS = {
    "alice": "alice@neuralmatrix093.onmicrosoft.com",
    "bob": "bob@neuralmatrix093.onmicrosoft.com",
}


async def run() -> int:
    registration = json.loads((ROOT / "entra-app-registration.json").read_text())
    secret = json.loads((ROOT / "entra-client-secret.json").read_text())
    with httpx.Client(timeout=15, trust_env=False, follow_redirects=False) as credential_client:
        graph_token, _ = graph_app_token(
            tenant_id=registration["home_tenant"],
            client_id=registration["client_id"],
            client_secret=secret["client_secret"],
            client=credential_client,
        )
    verified = {}
    async with httpx.AsyncClient(timeout=15, trust_env=False, follow_redirects=False) as client:
        resolver = GraphEmployeeIdentityResolver(
            tenant_id=registration["home_tenant"],
            graph_access_token=graph_token,
            client=client,
        )
        for label, upn in TEST_USERS.items():
            response = await client.get(
                "https://graph.microsoft.com/v1.0/users/" + quote(upn, safe=""),
                params={"$select": "id,userPrincipalName,accountEnabled,userType"},
                headers={"Authorization": "Bearer " + graph_token},
                follow_redirects=False,
            )
            print("GRAPH_SYNTHETIC_EMPLOYEE_LOOKUP", label, response.status_code)
            if response.status_code != 200:
                print("IDENTITY_VALIDATION_FAILED", label)
                return 2
            record = response.json()
            try:
                object_id = str(UUID(record["id"]))
                employee = await resolver.verify_employee(object_id=object_id)
                if employee.user_principal_name != upn:
                    raise MicrosoftIdentityResolutionError("GRAPH_UPN_DID_NOT_MATCH_APPROVED_LAB_IDENTITY")
            except (ValueError, KeyError, TypeError, MicrosoftIdentityResolutionError):
                print("IDENTITY_VALIDATION_FAILED", label)
                return 2
            verified[label] = {
                "tenant_id": employee.tenant_id,
                "object_id": employee.object_id,
                "user_principal_name": employee.user_principal_name,
                "sharepoint_login_name": employee.sharepoint_login_name,
            }
            print("GRAPH_SYNTHETIC_EMPLOYEE_VERIFIED", label)
    if len(verified) != len(TEST_USERS):
        return 2
    directory = ROOT / "sharepoint-rest-validation"
    directory.mkdir(mode=0o700, exist_ok=True)
    target = directory / "synthetic-verified-employees.json"
    pending = directory / "synthetic-verified-employees.json.new"
    descriptor = os.open(str(pending), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(verified, stream, indent=2)
        stream.write("\n")
    pending.replace(target)
    print("VERIFIED_GRAPH_MEMBER_IDENTITIES_SAVED_LOCALLY", len(verified))
    print("SHAREPOINT_EFFECTIVE_ACL_PROOF_STILL_REQUIRED")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
