"""Explicitly scoped real SharePoint Alice revoke/restore proof on a synthetic file.

Never changes tenant roles, site grants, Microsoft security defaults, or
production Protect. Default is read-only. Uses only certificate-authorized
Sites.Selected on one fixed test site and exact synthetic finance file.
All errors fail closed, with an independent recovery file and restore-only mode.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import httpx

from connectors.microsoft365.sharepoint_effective import SharePointEffectiveAccessProbe
from packages.auth.microsoft_certificate import sharepoint_rest_app_token

HOME = Path.home()
PRIVATE = HOME / ".config/accessproof/sharepoint-rest-validation"
REG = HOME / ".config/accessproof/entra-app-registration.json"
SITE = "https://neuralmatrix093.sharepoint.com/sites/AccessProof-Validation-20261027"
LIST = "8200ffae-ba10-42c5-bfa9-8f7ac155c5c4"
ITEM = 2
ITEM_ROOT = f"{SITE}/_api/web/lists(guid'{LIST}')/items({ITEM})"
RECOVERY = PRIVATE / "pending-finance-alice-restore.json"
EVIDENCE = PRIVATE / "synthetic-revocation-observations.json"


class RevocationError(RuntimeError):
    pass


async def _request(
    client: httpx.AsyncClient, method: str, url: str, token: str,
    *, content: bytes | None = None,
) -> httpx.Response:
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json;odata=nometadata"}
    return await client.request(
        method, url, headers=headers, follow_redirects=False, content=content,
    )


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true", help="Execute explicitly approved synthetic revoke/restore test")
    parser.add_argument("--restore-only", action="store_true", help="Recover a previously interrupted exact synthetic grant")
    parser.add_argument("--acknowledge-synthetic", action="store_true")
    args = parser.parse_args()
    if args.execute and (args.restore_only or not args.acknowledge_synthetic):
        raise RevocationError("EXPLICIT_SYNTHETIC_ACKNOWLEDGMENT_REQUIRED")
    if PRIVATE.is_symlink() or (PRIVATE.stat().st_mode & 0o077):
        raise RevocationError("PRIVATE_EVIDENCE_DIRECTORY_UNSAFE")
    if RECOVERY.is_symlink():
        raise RevocationError("RECOVERY_FILE_SYMLINK_UNSAFE")
    if RECOVERY.exists() and not args.restore_only:
        raise RevocationError("PENDING_RESTORE_MUST_RUN_FIRST")
    reg = json.loads(REG.read_text())
    people_file = PRIVATE / "synthetic-verified-employees.json"
    if people_file.is_symlink() or not people_file.is_file():
        raise RevocationError("VERIFIED_IDENTITY_BINDING_MISSING")
    people = json.loads(people_file.read_text())
    if set(people) != {"alice", "bob"}:
        raise RevocationError("EMPLOYEE_BINDINGS_UNEXPECTED")
    async with httpx.AsyncClient(timeout=18, trust_env=False, follow_redirects=False) as client:
        token = await sharepoint_rest_app_token(
            tenant_id=reg["home_tenant"], client_id=reg["client_id"],
            sharepoint_host="neuralmatrix093.sharepoint.com",
            private_key_file=PRIVATE / "client-private.pem",
            certificate_der_file=PRIVATE / "client-public.cer",
            client=client,
        )
        probe = SharePointEffectiveAccessProbe(site_url=SITE, sharepoint_access_token=token, client=client)
        alice = people["alice"]["sharepoint_login_name"]
        bob = people["bob"]["sharepoint_login_name"]

        async def actual() -> dict[str, bool]:
            return {
                "alice": await probe.can_view_item(list_id=LIST, item_id=ITEM, verified_login_name=alice),
                "bob": await probe.can_view_item(list_id=LIST, item_id=ITEM, verified_login_name=bob),
            }

        async def assignments() -> tuple[int, int]:
            unique = await _request(client, "GET", ITEM_ROOT + "?$select=Id,HasUniqueRoleAssignments", token)
            if unique.status_code != 200 or unique.json().get("HasUniqueRoleAssignments") is not True:
                raise RevocationError("ITEM_MUST_HAVE_UNIQUE_ACL")
            response = await _request(
                client, "GET", ITEM_ROOT + "/roleassignments?$expand=Member,RoleDefinitionBindings", token
            )
            if response.status_code != 200:
                raise RevocationError("DIRECT_ITEM_ROLE_ASSIGNMENTS_UNREADABLE")
            rows = response.json().get("value", [])
            if len(rows) != 2:
                raise RevocationError("SYNTHETIC_ITEM_ROLE_ASSIGNMENTS_CHANGED")
            targets = [row for row in rows if str(row.get("Member", {}).get("LoginName", "")).casefold() == alice.casefold()]
            if len(targets) != 1 or len(targets[0].get("RoleDefinitionBindings", [])) != 1:
                raise RevocationError("ALICE_ROLE_NOT_UNIQUE")
            role = targets[0]["RoleDefinitionBindings"][0]
            if role.get("Name") != "Read":
                raise RevocationError("ALICE_ROLE_IS_NOT_READ")
            # Ensure the other grant is an administrator Full Control grant,
            # which this test never changes.
            others = [row for row in rows if row is not targets[0]]
            if len(others) != 1 or "Full Control" not in [
                b.get("Name") for b in others[0].get("RoleDefinitionBindings", [])
            ]:
                raise RevocationError("ADMINISTRATOR_GRANT_NOT_PRESERVED")
            principal_id = targets[0].get("PrincipalId")
            role_id = role.get("Id")
            if type(principal_id) is not int or type(role_id) is not int:
                raise RevocationError("ROLE_IDS_MISSING")
            return principal_id, role_id

        baseline = await actual()
        if args.restore_only:
            if not RECOVERY.exists():
                print("NO_PENDING_RESTORE")
                return 0
            pending = json.loads(RECOVERY.read_text())
            principal_id, role_id = pending.get("principal_id"), pending.get("role_id")
            if type(principal_id) is not int or type(role_id) is not int:
                raise RevocationError("RECOVERY_PAYLOAD_INVALID")
        else:
            principal_id, role_id = await assignments()
            if baseline != {"alice": True, "bob": False}:
                raise RevocationError("INITIAL_EFFECTIVE_ACCESS_CHANGED")
        if not args.execute and not args.restore_only:
            print("DRY_RUN_PASSED: exact synthetic finance item and Alice Read-only role verified")
            print("BASELINE_VALIDATED", baseline == {"alice": True, "bob": False})
            print("NO_SHAREPOINT_ACL_CHANGED")
            return 0

        async def restore() -> None:
            response = await _request(
                client, "POST",
                ITEM_ROOT + f"/roleassignments/addroleassignment(principalid={principal_id},roledefid={role_id})",
                token, content=b"",
            )
            # 400/409 can mean grant already restored; re-read the actual ACL.
            if response.status_code not in {200, 201, 204, 400, 409}:
                raise RevocationError(f"RESTORE_HTTP_{response.status_code}")
            for _ in range(8):
                current = await actual()
                if current == {"alice": True, "bob": False}:
                    return
                await asyncio.sleep(2)
            raise RevocationError("ALICE_PERMISSION_RESTORE_NOT_OBSERVED")

        if args.restore_only:
            await restore()
            RECOVERY.unlink()
            print("RECOVERED_ORIGINAL_SYNTHETIC_ALICE_ROLE")
            return 0

        payload = {"principal_id": principal_id, "role_id": role_id,
                   "site": SITE, "list": LIST, "item": ITEM,
                   "started_at": datetime.now(timezone.utc).isoformat()}
        fd = os.open(str(RECOVERY), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as out:
            json.dump(payload, out)
            out.flush()
            os.fsync(out.fileno())
        revoked = False
        failure = None
        try:
            response = await _request(
                client, "POST",
                ITEM_ROOT + f"/roleassignments/getbyprincipalid({principal_id})/deleteobject",
                token, content=b"",
            )
            if response.status_code not in {200, 204}:
                raise RevocationError(f"REVOKE_HTTP_{response.status_code}")
            for _ in range(9):
                value = await actual()
                if value == {"alice": False, "bob": False}:
                    revoked = True
                    break
                await asyncio.sleep(2)
            if not revoked:
                raise RevocationError("PROVIDER_REVOCATION_NOT_OBSERVED")
        except Exception as exc:
            failure = exc
        finally:
            try:
                await restore()
            except Exception as exc:
                # Leave recovery instructions when restoration fails.
                raise RevocationError("URGENT_SYNTHETIC_GRANT_RESTORE_REQUIRED") from exc
            RECOVERY.unlink()
        if failure:
            raise RevocationError("REVOCATION_TRIAL_FAILED_RESTORED") from failure
        evidence = {
            "schema": "accessproof.live_sharepoint_revoke_restore/v1",
            "site_scope": "one synthetic validation site",
            "list_id": LIST, "item_id": ITEM,
            "before": baseline,
            "during": {"alice": False, "bob": False},
            "after": {"alice": True, "bob": False},
            "actual_provider_read_after_revocation": True,
            "original_grant_restored": True,
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "production_source_certification": "NOT_ISSUED",
            "employee_oidc_not_proven_by_this_trial": True,
        }
        temp = EVIDENCE.with_suffix(".tmp")
        fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(evidence, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, EVIDENCE)
        print("LIVE_SYNTHETIC_REVOKE_AND_RESTORE_PASSED")
        print("ORIGINAL_PERMISSION_RESTORED", True)
        print("NO_SOURCE_CERTIFICATE_ISSUED")
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except Exception as error:
        # Never log tokens, principal IDs, private source contents or secret paths.
        print("REVOCATION_TEST_FAILED", str(error) if isinstance(error, RevocationError) else type(error).__name__)
        raise SystemExit(2)
