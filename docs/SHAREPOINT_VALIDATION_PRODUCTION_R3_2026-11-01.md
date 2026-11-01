# SharePoint Validation r3 — Production deployment (2026-11-01)

## Release details

- **Release image:** `accessproof/api:sharepoint-validation-r3-20261101`
- **Previous API image, retained for rollback:** `accessproof/api:auth-limiter-r2-20261101`
- **Deployment location:** AccessProof production EC2, `eu-north-1`.
- **Deployment method:** Image built from the existing production API image,
  adding only read-only SharePoint validation modules and operator scripts.
  Runtime HTTP routes, policy enforcement, provider release flags and database
  schema were not modified.
- **Artifact SHA-256:** `67952b19ec56a19d568b796b6c53278b99c96fd6b04d543438402c4d7ab35aa0`.
- **Rollback:** An exact predeployment `.env` copy resides within
  `/home/ubuntu/accessproof-releases/sharepoint-validator-r3-20261101/`.
  Roll back by restoring the previous API image variable, validating Compose
  and recreating only the API service. Never expose or paste the environment file.

## Validation modules deployed inside the API image

- `/app/scripts/sharepoint_validation_readiness.py` — database-backed
  read-only readiness report, fail closed for absent or malformed checks.
- `/app/scripts/read_only_sharepoint_effective_trial.py` — test site
  certificate-authenticated six-cell Alice/Bob permission matrix.
- `/app/scripts/sharepoint_trial_verdict.py` — exact synthetic expected ACLs.
- `/app/scripts/inspect_approved_test_site_app_role.py` — read-only
  Graph site-grant inspection.
- `/app/scripts/verify_synthetic_microsoft_users.py` — immutable Graph
  identity resolution.
- Modules for Entra certificate authentication, Graph identity validation
  and SharePoint REST token scope diagnostics.

**No private key, certificate client secret, access token or source
certification signing key was copied into the Docker image.** The external
SharePoint trial scripts require separately approved operator credentials
before they can run live. Deploying them does not supply those credentials.

## Proof after deployment

Command on production:

```bash
docker exec accessproof-api-1 python -m scripts.sharepoint_validation_readiness \
  --application sharepoint-rag-staging
```

Result:

```json
{
  "application_mode": "protect_pending",
  "certificate_verified": false,
  "diagnostic_type": "READ_ONLY_LOCAL_CONTROL_PLANE",
  "failed_checks": [
    "BUFFERED_RESPONSE_GATE_READY",
    "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED",
    "CUSTOMER_RAG_CUTOVER_NOT_VERIFIED",
    "LAYER1_INTEGRATION_CONFIRMED",
    "LAYER2_INTEGRATION_CONFIRMED",
    "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED",
    "PRODUCTION_OIDC_READY",
    "PROVENANCE_READY",
    "V1_PROVIDER_SCOPE"
  ],
  "readiness": "NO_GO",
  "safe_to_enable_protect": false
}
```

The diagnostic exits 2 as designed when evidence is absent. It is
not a certificate issuer and cannot activate customer Protect.

- API Docker container: **healthy**.
- Public API readiness: HTTP 200; PostgreSQL and Redis OK.
- Public login: HTTP 200.
- Bounded security smoke: **17/17 pass**.
- Post-release readiness/pairing source tests: **7 passed**.
- Full focused SharePoint validation regression tests: **69 passed**.
- Remote production root filesystem: around **92% used** (1.5 GiB free).
- Original r2 API image preserved.

## Genuine unresolved security work

Real Microsoft SharePoint `GetUserEffectivePermissions` still reports
`SHAREPOINT_PERMISSION_SCOPE_UNAVAILABLE` for all six synthetic Alice/Bob
item checks. The existing operator Graph app cannot list the selected site's
grants (403), so additional administrator-granted, narrowly scoped permission
is necessary for live certification. Protect remains in `protect_pending`
and the Guard/Gateway correctly deny unverified access.

**Release verdict: READ-ONLY VALIDATION DEPLOYED; SHAREPOINT PROTECT NO-GO.**
