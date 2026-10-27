# AccessProof SharePoint Compatibility Audit — 2026-10-27

Repository: `/home/white-devil/Downloads/accessproof/f15`
Security release status: **SHADOW ONLY — SHAREPOINT PROTECT NOT CERTIFIED**

## External provider evidence

The connected NeuralMatrix Microsoft account authenticated in Microsoft Graph. A live, read-only `list_drives` call returned HTTP 400 `Tenant does not have a SPO license.` (also observed earlier from root site discovery). The Microsoft 365 Business Basic subscription screen shows the trial is active, with available seats. These facts do not prove that the signed-in account's SharePoint Online service plan is assigned/enabled or that provisioning is complete.

The ChatGPT SharePoint account connection is not an AccessProof application credential. The local project's existing environment does not contain a configured operator Microsoft client ID/secret. No Graph data, SharePoint files, licenses, or permissions were altered in this audit.

## Code-read compatibility matrix

| Area | Local evidence | Verdict |
|---|---|---|
| SharePoint source creation | `apps/api/accessproof_api/app.py` validates tenant, site triple GUID, library GUID, drive/root | Implemented |
| Admin consent | Tenant-bound hashed state, Graph app token and source identity validation; expiry/reauth controls | Implemented locally |
| Microsoft Graph token renewal | Server/worker credentials, tenant-pinned OAuth token acquisition | Implemented locally; tenant not verified |
| Entra users/groups | Directory sync and transitive membership with stable IDs | Implemented locally |
| Graph inventory/delta | Root ancestry, bounded paging, URL validation and reconciliation | Implemented locally |
| Employee-effective authorization | Delegated `/me` ID + direct file request; no Graph-permission-list inference | Partially implemented |
| Native SharePoint ACLs | Site groups, inheritance, unique scopes, guests, links and OneDrive profiles | Not certified |
| Trusted content ingestion | `SharePointTrustedIngestion` attests root-scoped UTF-8 plain-text Graph documents | Local reusable bridge, **not wired into a live customer RAG route** |
| LLM/RAG Gateway | Gateway/Guard source binding and independent provider-live certificate gate | Implemented locally; no live Microsoft route validation |
| SharePoint employee SSO + demo RAG | No complete Entra employee-login + SharePoint-index demo wired | Not implemented |
| PDF/DOCX library documents | Ingestion bridge supports `text/plain` only | Unsupported by this bridge |
| Signed Protect release | Requires exact live source and independent effective ACL evidence | Blocked, correctly fail-closed |

## Fixes applied in this pass

1. **Graph content 302 verification** (`connectors/microsoft365/adapter.py`): a delegated user's 302 only proves provider access when Location is an absolute HTTPS SharePoint/OneDrive delivery URL; malformed, absent, off-host or nonstandard redirects produce an inconclusive error rather than a false access result. Does not follow the content redirect with the delegated bearer token.
2. **Graph admin HTTP redirect**: each Graph request explicitly disables redirects, including injected clients that otherwise follow Location. Prevents administrator bearer-token leakage.
3. **Business Basic licensing diagnostics**: the observed `Tenant does not have a SPO license` Graph error is mapped to a safe `MICROSOFT_SHAREPOINT_SERVICE_NOT_READY` code rather than a generic failure.
4. **Backend/UI status propagation** (`apps/api/accessproof_api/app.py`, `web-v2/app/sources/page.tsx`): show the specific SharePoint readiness issue on source onboarding/validation; persist stable sanitized status rather than raw Graph exception text.
5. **Trusted ingestion tenant/profile binding** (`connectors/microsoft365/trusted_ingestion.py`): require matching tenant hint and an exact SharePoint site + library before signing source content; reject cross-tenant/missing-profile metadata.
6. **Microsoft app secret redirect leakage** (`packages/auth/microsoft_consent.py`): explicitly disable redirects on client-credentials POST, even with a caller-injected redirect-following HTTP client.
7. Added adverse/regression coverage in `tests/security/test_microsoft_graph_compatibility.py`, `tests/unit/test_sharepoint_trusted_ingestion.py`, and `tests/integration/test_microsoft_admin_consent.py`. Existing tests and previous working-tree modifications were preserved.

## Validation results

- Post-change Microsoft/SharePoint/Gateway focused suite: **154 passed**, exit code 0.
- New token endpoint redirect test and consent/delegation subset after last edit: **25 passed**, exit code 0 (overlaps focused suite; not additive).
- Ruff: passed on modified components.
- Mypy: passed on Microsoft adapter, trusted ingestion and related preflight code.
- Python compile: passed.
- Frontend ESLint and `tsc --noEmit`: passed.
- No unauthorized live-tenant mutation; no live SharePoint permissions or employee LLM response verified.

## Steps remaining before a customer pilot

1. In Microsoft 365 Admin Center, verify the active Business Basic trial *is assigned* to the test user with SharePoint Online enabled; confirm SharePoint Admin Center and site provisioning work. Repeat read-only Graph discovery. Do not buy additional seats without necessity.
2. Register a dedicated test Entra app for AccessProof, grant the minimum Graph permissions for the isolated validation site, and store app credentials privately in API/worker environment; do not enter app secrets in the web Sources form or send them in chat.
3. Create a dedicated SharePoint library/folder with synthetic canaries and test accounts Alice/Bob/Charlie; save immutable tenant/site/library/drive/folder IDs.
4. Run the read-only preflight script `scripts/validate_microsoft_trial_preflight.py --live` using tenant-bound app credentials, then separately run true delegated employee ACL/permission-revocation cases.
5. Wire and validate a customer-side SharePoint text ingestion + Entra employee login + Gateway route, including cache hits, streaming, negative controls, group inheritance, link paths, source invalidation, fail-closed policy refresh and signed evidence. Keep SharePoint Protect disabled until all checks are actually observed in the test tenant.
6. Microsoft announced a future retirement of preauthenticated content URLs. Before the provider's transition, implement and test the Graph token-authenticated contentStream path as documented. Do not assume this initial text-only preauth bridge is future-proof.

**Release verdict remains SHADOW ONLY / NOT CERTIFIED.**
