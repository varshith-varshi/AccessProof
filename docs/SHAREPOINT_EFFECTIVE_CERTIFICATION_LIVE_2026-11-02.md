# Live SharePoint effective-access certification audit — 2026-11-02

Status: BLOCKED BY MICROSOFT ADMIN DELEGATED CONSENT; no source certificate issued.
Protect remains protect_pending and fail-closed.

## Independently observed against the synthetic validation site

- Authenticated SharePoint REST app-only with a private-key-backed
  certificate. SharePoint token accepted; certificate OAuth response HTTP 200.
- Token claims contain SharePoint audience, Sites.Selected application role,
  correct tenant, and appidacr=2.
- The site /_api/web, library and selected list items return HTTP 200.
- The specific GetUserEffectivePermissions REST endpoint returned HTTP 403
  for Alice and Bob on each of three synthetic items (6/6 failures).
- Web roleassignments REST endpoint returned 403.
- Microsoft Graph app-only directory revalidation of both immutable employee
  object IDs and SharePoint login mappings succeeded.
- Microsoft Graph delegated administrator site /permissions GET returned
  Forbidden. Decoded current Azure CLI delegated Graph OAuth scope
  does NOT contain Sites.FullControl.All.
- A connected SharePoint integration separately confirmed the test site,
  three named synthetic list items, and sharing-permission entries.
  Those sharing entries are NOT authoritative effective ACLs and cannot
  authorize production Protect.

## The next required external authorization

1. The tenant administrator must explicitly approve an Azure CLI delegated
   Microsoft Graph Sites.FullControl.All consent/MFA flow. This is a privileged
   administrative scope; it must never be silently assigned to the AccessProof
   customer application.
2. After consent, review target site grants for the existing test app,
   using scripts/configure_sharepoint_rest_admin.py (dry-run by default).
3. Only with explicit approved scope, apply the least sufficient role at
   the single synthetic test site; never grant tenant-wide Sites.FullControl.All
   application permission or disable Microsoft security defaults.
4. Run the read-only certificate-backed item effective-permission probe.
   Require all six exact allow/deny observations match the synthetic oracle.
5. Passing those six cells alone is NOT sufficient to certify production:
   verify employee OIDC sessions, controlled revocation, inheritance/groups,
   layer-1/2 Gateway route challenge, provenance and cached-answer safety.
6. Record independent signed, scoped and expiring evidence only after all
   applicable provider-backed tests pass. Customer cutover remains an
   independent explicit approval.

## Commands (do not execute without the required human authorization)

- Read-only item trial:
  ACCESSPROOF_SHAREPOINT_CERTIFICATE_PROBE=1
  .venv/bin/python scripts/read_only_sharepoint_effective_trial.py
- Site grant dry-run:
  .venv/bin/python scripts/configure_sharepoint_rest_admin.py

This report is a diagnostic, not a certification grant or deployment claim.
