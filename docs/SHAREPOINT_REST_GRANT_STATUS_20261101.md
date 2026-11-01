# AccessProof SharePoint authorization continuation — 1 November 2026

## Verified live changes in NeuralMatrix093 tenant

- AccessProof Entra application has a public RSA certificate registered.
- The SharePoint Online enterprise service principal's
  `Sites.Selected` application role was assigned to the AccessProof
  service principal and independently verified using
  `/servicePrincipals/{id}/appRoleAssignments`.
- A NEW certificate-based SharePoint OAuth token has:
  `aud=00000003-0000-0ff1-ce00-000000000000`,
  `roles=[Sites.Selected]`, `appidacr=2`.
- The approved site `/_api/web` returns HTTP **200**.
- **All six** `GetUserEffectivePermissions` checks on synthetic
  list items 2, 3, 4 for Alice and Bob still fail
  `SHAREPOINT_PERMISSION_SCOPE_UNAVAILABLE`.
- No user document permissions were changed. No effective-permission
  source certification was issued.

## Hardened validation source (commit 8fbb2c5)

1. `scripts/configure_sharepoint_rest_admin.py` now independently
   verifies **actual app-role assignment**. The Azure CLI
   `admin-consent` command can return success without adding a new
   SharePoint resource-app-role assignment.
2. The same script returns
   `SITE_PERMISSION_MANAGEMENT_BLOCKED` clearly when the
   delegated Microsoft Graph identity cannot list/modify site grants.
3. `scripts/read_only_sharepoint_effective_trial.py` now exits
   **nonzero** for any failed effective-permission request.
   A prior version falsely exited zero even with six failed checks.
4. The read-only test now requires this six-cell truth table:

   | Identity | finance_alice | engineering_bob | shared_control |
   | --- | --- | --- | --- |
   | Alice | ALLOW | DENY | ALLOW |
   | Bob | DENY | ALLOW | ALLOW |

   Any missing result, extra identity, non-boolean permission, or unexpected
   allow/deny blocks the trial; 15 synthetic tests pass.
5. This synthetic matrix alone **never** authorizes a real Protect release.
   Additional real revocation/OIDC/Layer1/2 verification is mandatory.

## Other live customer-side findings

- Running SharePoint RAG lab has **3 documents, 3 signed chunks** indexed.
- The Gateway liveness endpoint returns HTTP 200 but readiness HTTP 503
  with `GUARD_NOT_READY`.
- The local Guard has policy version **8**, application
  `sharepoint-rag-staging` bound to `protect`, and
  `source_acl_healthy=False`, so it intentionally denies release.
- A test unauthenticated chat request returned HTTP **401** and
  `IDENTITY_TOKEN_REQUIRED`. No unsafe bypass was enabled.
- The live AccessProof web and API releases remain healthy.

## Exact remaining Microsoft administrator dependency

The signed-in user is a Global Administrator but the current Azure CLI
Microsoft Graph delegated OAuth token does **not** contain
`Sites.FullControl.All`. The Microsoft site-permission API requires
a separately MFA-approved delegated administrator scope and site
membership. The AccessProof customer application must NOT be granted
tenant-wide `Sites.FullControl.All`.

The administrator should run:

```bash
az login --use-device-code \
  --tenant 6479e7ca-b256-4ebc-a408-871b9046547c \
  --scope https://graph.microsoft.com/Sites.FullControl.All
```

Complete the browser's MFA/consent as this admin. Verify permission from
the issued token before performing any site-scoped grant. Then rerun:

```bash
cd ~/Downloads/accessproof/f15
.venv/bin/python scripts/configure_sharepoint_rest_admin.py \
  --apply --approve-test-site-fullcontrol
ACCESSPROOF_SHAREPOINT_CERTIFICATE_PROBE=1 \
  .venv/bin/python scripts/read_only_sharepoint_effective_trial.py
```

The operator script is scoped to the single approved **synthetic** site.
Do not run an Azure CLI login for this purpose without checking the
requested scopes. Microsoft MFA/Security Defaults must stay enabled.

Microsoft documentation:
- https://learn.microsoft.com/en-us/graph/api/site-post-permissions
- https://learn.microsoft.com/en-us/sharepoint/dev/solution-guidance/security-apponly-azuread

**Result:** The Entra certificate/app-role failures are fixed; site-level
effective ACL verification is blocked pending administrator delegated
site-grant authorization. Production Protect is NOT certified.
