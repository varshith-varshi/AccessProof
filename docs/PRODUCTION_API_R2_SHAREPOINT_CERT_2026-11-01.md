# AccessProof — verified production and SharePoint certification work (1 November 2026)

## Deployed on AWS EC2 (eu-north-1)

- Web: `accessproof/web-v2:onboarding-source-r6-20261101` — healthy.
  Canonical three-step onboarding is source-built with versioned assets.
- API: `accessproof/api:auth-limiter-r2-20261101` — healthy.
  This is a minimal overlay of the previous healthy production image. Only
  `app.py` changes, adding bounded authentication-rate-limiter storage.
- Existing production pairing endpoints, SharePoint certification gate,
  worker, database, Redis, and Nginx preserved.
- Postdeployment security smoke: **17/17 checks pass**.
- The previous API and web images and predeployment environment copies are
  retained for rollback. No production database migration occurred.
- AWS Systems Manager is online for the EC2 instance, with a dedicated
  `AmazonSSMManagedInstanceCore` instance role. Temporary SSH rules are
  removed after deployment. Do not expose SSH to 0.0.0.0/0.

## Recovered canonical backend sources

The local checkout was missing the production `gateway_pairing.py`, three
pairing endpoints, and an existing certified SharePoint scope helper. The
running production code was used as the source of truth and restored into
`apps/api/accessproof_api/`. The only remaining API runtime delta is
the bounded authentication-rate-limiter change.

The established feature flag is
`ACCESSPROOF_MICROSOFT_CERTIFIED_PROTECT_ENABLED`. In the running production
API the flag is enabled. That alone does **not** certify any source.

The production DB has **0 persisted SourceEffectiveCertification rows**.
Therefore SharePoint Protect remains blocked even though the flag is on.

## The live Microsoft REST authorization blocker

The Entra app for the synthetic SharePoint tenant currently obtains a
SharePoint-audience OAuth token with **no SharePoint application roles**.
In a read-only check, `/_api/web` returned 401.

Microsoft's official SharePoint documentation additionally requires
**certificate-based app-only authentication for SharePoint REST/CSOM**.
A client secret alone cannot satisfy this REST restriction.

Reference: https://learn.microsoft.com/en-us/sharepoint/dev/solution-guidance/security-apponly-azuread

Current Azure CLI login attempts fail with `AADSTS530035` (Security
Defaults). The role/consent/certificate cannot be applied before an
authorized tenant admin completes the tenant's legitimate MFA/device
requirements. Do not disable Microsoft Security Defaults.

## Prepared for the synthetic test tenant

- Certificate private key:
  `~/.config/accessproof/sharepoint-rest-validation/client-private.pem`
  (permissions 0600; NEVER upload, email or print).
- Public certificate for the Entra app:
  `~/.config/accessproof/sharepoint-rest-validation/client-public.pem`.
- Certificate-authenticated OAuth implementation:
  `packages/auth/microsoft_certificate.py`.
- Scope/claim preflight:
  `connectors/microsoft365/sharepoint_authorization.py`.
- Verified immutable Entra object-id to SharePoint login resolver:
  `connectors/microsoft365/graph_employee_identity.py`.
- Read-only real-provider trial:
  `scripts/read_only_sharepoint_effective_trial.py`.
- Idempotent, dry-run-by-default admin setup:
  `scripts/configure_sharepoint_rest_admin.py`.

## Exactly what the tenant administrator must do

From the authorized Ubuntu workstation, complete interactive sign-in
including MFA, in the **NeuralMatrix093** tenant:

```bash
az login --tenant 6479e7ca-b256-4ebc-a408-871b9046547c \
  --scope https://graph.microsoft.com//.default
```

After the tenant legitimately authorizes the administrator, run the
single operator script. It adds only the SharePoint Online application
`Sites.Selected` role, appends ONLY the public certificate, requests
admin consent, and grants **site-scoped** access only to the approved
synthetic test SharePoint site. The fullcontrol flag is intentionally
explicit because effective ACL inspection may require that level at
the site, not across the tenant.

```bash
cd ~/Downloads/accessproof/f15
.venv/bin/python scripts/configure_sharepoint_rest_admin.py \
  --apply --approve-test-site-fullcontrol
```

Once Microsoft confirms the grant, run:

```bash
ACCESSPROOF_SHAREPOINT_CERTIFICATE_PROBE=1 \
  .venv/bin/python scripts/read_only_sharepoint_effective_trial.py
```

A successful REST token does **not** mean certification is complete. A
separate provider-live evidence issuer, cross-checked stable employee
identities, inherited ACLs, real Alice/Bob positive/negative tests,
revocation tests, Guard Layer 1/2 and provenance/cached-answer evidence
must all pass before a signed source certificate is issued.

## Test evidence

- Full Python regression suite completed with exit code **0**.
- Focused Microsoft security, SharePoint, rate limiter and Guard suites
  passed with exit code **0**.
- New certificate-auth primitive: 11 tests passed.
- New Graph employee identity resolver: 13 tests passed.
- New SharePoint token scope/feature gate: 13 tests passed.
- Recovered pairing endpoint tests pass.
- Ruff and Mypy checks pass for changed modules.
- The admin setup dry-run makes no tenant mutation.

## Current verdict

**Production web and API security updates deployed and healthy.**
**SharePoint Protect is NOT production certified or activated.**

Never fabricate SharePoint results, turn off Security Defaults, issue
a certificate from self-reported evidence, or enable Protect before
real live authorization and revocation checks.
