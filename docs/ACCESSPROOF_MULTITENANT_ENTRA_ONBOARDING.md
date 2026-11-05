# AccessProof — one multitenant Microsoft Entra application

**Implementation status (2026-10-27):** the real AccessProof Entra app was
registered in the operator home tenant (`AzureADMultipleOrgs`) and its three
Microsoft Graph application roles were verified granted in that home tenant.
Application client ID: `b8424d54-5428-4d35-ae2c-639de7e512a9`.
A 90-day operator client secret exists **only** in the local Ubuntu restricted
credential file, not in production. The API/worker code and Docker Compose
credential wiring are prepared, and a fresh-image build plus isolated database
migration test succeeded. The source UI is live; the matching backend images
have NOT been transferred or deployed and the live database has NOT been
migrated. **No Sites.Selected customer site grant, real customer-source
connection or end-to-end Protect validation has succeeded.**

## Architecture

There is ONE operator-owned application registration named **AccessProof**
in the NeuralMatrix / AccessProof home Entra tenant, with
`signInAudience=AzureADMultipleOrgs`. Every customer tenant authorizes that
same **client ID**, creating a corresponding enterprise service principal in
its own directory. AccessProof never asks a customer to create an app or send
its app secret. An administrator in that customer tenant grants consent.

The backend stores the tenant UUID in each explicitly approved source
credential and uses its tenant-specific Microsoft token endpoint. Consent state
is single-use, source-scoped, organisation-scoped, tenant-bound and expires in
10 minutes. Existing Guard identity graph rejects mixing two Microsoft tenant
UUIDs within one AccessProof organization until a full identity-scoping
migration exists. Different AccessProof organizations may use different tenants.

## Register once — operator, not customers

The Microsoft administrator needs app registration privileges in the chosen
home tenant. The Azure CLI is needed only to run the provisioning helper.

1. `az login --tenant <OPERATOR_HOME_TENANT_UUID>` (interactive sign-in).
2. Preview without making changes:
   `python scripts/register_accessproof_multitenant_entra.py`.
3. After reviewing the requested Graph application permissions, run:
   `python scripts/register_accessproof_multitenant_entra.py --apply --create-secret`.
4. This creates **one** app named AccessProof, audience
   `AzureADMultipleOrgs`, web redirect URI
   `https://api.accessproof.in/api/v1/current/sources/microsoft-admin-consent/callback`,
   Graph *application* roles `Sites.Selected`, `User.Read.All`, and
   `Group.Read.All`. The operator's Azure login must be entitled to manage
   application registrations; an administrator may need to grant the relevant
   Graph app-management permissions.
5. The app ID and home tenant ID are written to a private file:
   `~/.config/accessproof/entra-app-registration.json`. A separately requested
   90-day secret is stored at
   `~/.config/accessproof/entra-client-secret.json` with mode 0600;
   never print, paste or commit this file. Rotate it before expiry. Prefer
   certificate/managed-secret storage for long-lived enterprise use.
6. Configure `ACCESSPROOF_MICROSOFT_CLIENT_ID` and
   `ACCESSPROOF_MICROSOFT_CLIENT_SECRET` in the backend secret store. The
   API **and** worker need them, and `docker-compose.ec2.yml` /
   `docker-compose.production.yml` now pass them through. Never put the
   secret in a browser form, frontend bundle, customer RAG config, or Git.
7. Deploy the compatible API/worker build and any outstanding Alembic
   migrations after database backup and a reviewed maintenance window.
   Do not replace the API while schema is behind the new image.
8. Verify, while signed in as an AccessProof administrator, that
   `GET /api/v1/current/sources/microsoft-admin-consent/status`
   returns `configured: true`. This is configuration readiness, not Microsoft
   authorization. Verify genuine consent using an isolated pilot tenant.

For a portal-only approach: Entra Admin Center → App registrations → New
registration → **Accounts in any organizational directory** → Web callback
above → API permissions → Graph → **Application permissions** as above →
Certificates & secrets. Do not create multiple customer-specific apps.

## Customer process — one application reused

1. Customer signs in to `https://app.accessproof.in` as the organization's
   AccessProof administrator.
2. The customer selects Sources → Microsoft 365 + SharePoint, supplies their
   tenant ID, verified site/library/drive ID, and bounded root folder ID.
   **The current screen still requires these identifiers manually; a secure
   site picker has not been implemented.** Do not suggest otherwise.
3. AccessProof redirects to a **tenant-specific Microsoft admin-consent**
   screen for our single registered client ID. A tenant admin approves only
   the application permissions actually configured in the app registration.
4. **Critical second grant:** `Sites.Selected` consent grants access to
   **zero** sites by itself. A separate, authorized SharePoint administrator
   must explicitly grant the AccessProof application access to the approved
   site. The `read` role can cover basic file and metadata reads, but **do not
   assert that it suffices for permission-certification operations.** In the
   November 2026 production-equivalent tenant validation, `fullcontrol` was
   needed for the effective-permissions certification path. This is an
   elevated **site-scoped** permission and must be disclosed, approved by the
   customer's security administrator, and revoked when no longer needed.
   It is not equivalent to tenant-wide `Sites.FullControl.All`, which must
   never be requested silently. The validated full-control path must not be
   described as a least-privilege read-only integration. A future narrower
   design requires fresh live evidence before reducing this requirement.
   The grant uses a separate administrator's PnP PowerShell or Graph access;
   AccessProof never auto-escalates its own privileges.
5. The one-time callback validates consent and exact tenant binding. If the
   selected-site grant already exists, it validates the approved
   drive/folder/site/library boundary and queues directory/ACL sync. If that
   grant is still pending, it stores only tenant-bound, short-lived Graph
   access credentials, records `MICROSOFT_SITE_ACCESS_GRANT_REQUIRED` and
   stays unconfigured. After the administrator adds the approved site grant,
   the customer clicks **Sources → Validate** to verify scope and queue fresh
   permission/directory synchronization. No second admin consent is required.
   The operator application secret is never put in a customer source record.
6. Customer enrolls the normal Guard and installs the reviewed Gateway beside
   its RAG pipeline. Protect is **not** automatically enabled: site metadata,
   group membership, employee identity, effective ACL and RAG-route integrity
   must pass independent production-equivalent tests.
7. The customer can revoke tenant admin consent or selected-site access at
   any time; these must result in fail-closed access, never stale ALLOW.

**Important (current implementation):** The source creation UI requires
site, drive and root identifiers **before** administrator consent. The
consent callback first verifies the tenant and obtains a short-lived token;
when the explicit selected-site grant does not exist yet, the callback
records `MICROSOFT_SITE_ACCESS_GRANT_REQUIRED` and redirects to
`?microsoft=site-grant-required`. It **does not discard valid admin consent**,
mark the source connected, or enable Protect. After an authorized admin adds
and independently reviews the selected-site grant, use **Sources → Validate**;
the separate validation path marks the source connected and queues fresh
permission and directory synchronization. Repeating consent is unnecessary
unless the original consent is revoked or other credentials change.

The customer must still work with an authorized technical contact for the
site grant and route certification. No fully autonomous third-party RAG
certification is claimed in the current product.

## Safeguards and rollout

- An app-only Graph token is **not** an employee's OIDC token. The Guard and
  Gateway must independently validate identity and source ACLs per request.
- The `User.Read.All` and `Group.Read.All` roles are tenant-wide directory
  reads; disclose these clearly in the consent review. Avoid
  `Group.ReadWrite.All` without a separate approved feature-level reason.
- A test tenant with SharePoint Online provisioned and verified is mandatory.
  The earlier trial Graph error `Tenant does not have a SPO license` remains
  a separate tenant service-readiness blocker.
- Current production API remains older than the new backend schema and lacks
  consent-readiness compatibility. Registering the Entra app alone does not
  fix it. Migration and release are a separately controlled operation.
- Do not claim universal RAG architecture compatibility or full SharePoint
  effective-permission certification from a consent success.

## 27 October 2026 selected-site consent recovery update

The new API source callback distinguishes a valid Microsoft tenant admin consent
from the absent site assignment (`MICROSOFT_SITE_ACCESS_GRANT_REQUIRED`).
An HTTP 403 during approved-root validation is handled conservatively:
the source is kept `not_configured`, validated identity remains empty,
prior ACL and directory sync cursors are invalidated, and the administrator
is guided to grant the selected site's access then press **Validate**.
A successful later validation queues fresh ACL and directory sync.
Other failures, including SharePoint licensing/provisioning errors and
invalid tenant/callback state, remain failures rather than being promoted.

The frontend message is deployed to the existing Sources page; the new API
logic remains LOCAL ONLY pending actual app registration, operator secrets,
controlled production schema migration, and verified live pilot.


## 27 October 2026 isolated-site admin grant and synthetic fixtures

- Graph beta SharePoint site creation succeeded at
  `https://neuralmatrix093.sharepoint.com/sites/AccessProof-Validation-20261027`.
- Dedicated site ID:
  `neuralmatrix093.sharepoint.com,9b00ec42-620a-4efc-acb3-f4d662c8ceb6,20231c9b-3196-4a5e-9ed0-0404090d5930`.
- `Sites.Selected` application **read** role to the permanent AccessProof app
  was created and read back successfully with a short-lived administrator
  service principal. The helper's service principal and app registration were
  deleted immediately afterward, confirmed through Microsoft Graph. The
  credential was not saved or printed.
- A dedicated `Synthetic-RAG-Test` folder exists in the site Documents library:
  - Drive: `b!QuwAmwpi_E6ss_TWYsjOtpscIyCWMV5KntAEBAkNWTCu_wCCELrFQr-pj3rBVcXE`
  - List: `8200ffae-ba10-42c5-bfa9-8f7ac155c5c4`
  - Folder item: `012JSJ74SOSX3HDJ2GXJBLWBEAD4WAJHZ2`
  - Alice-only: `finance_alice.txt` (`012JSJ74RLLD33Y3BPLFDZIMHHGT2SWMTP`)
  - Bob-only: `engineering_bob.txt` (`012JSJ74X46JMPG5ZRBJBKZIFY3AC43RQT`)
  - Alice+Bob: `shared_control.txt` (`012JSJ74RVIGYMKZU6J5EZ7EKZZO6JQGET`)
- SharePoint invitation actions created read grants with inheritance removal
  requested. A subsequent permission-list read showed exactly one named
  read grant on each user-only file and two on the shared control. These
  permission-inventory results do **not** establish employee-effective denial
  under inherited site administrators, access caches, or real user OIDC tokens.
- Alice's Entra immutable object ID: `67b731fb-c51c-4344-bbd2-63d5bf77a5d5`.
- Bob's Entra immutable object ID: `b7989860-d1bc-4cc3-a96c-35117a3ef9c4`.
- Sample non-secret local RAG configuration:
  `docs/entra_alice_bob_isolated_site_20261027.env.example`.

The AWS release images remain staged; production API/worker, Microsoft
secret, and database migration are still incomplete. Protect is OFF and
**no real Alice/Bob RAG leakage/revocation test has passed**.
