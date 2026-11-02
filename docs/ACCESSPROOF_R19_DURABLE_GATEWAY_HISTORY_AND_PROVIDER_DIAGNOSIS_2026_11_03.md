# AccessProof r19 — restore installation history without misreporting protection

## Confirmed root issues
1. The SharePoint app has a legitimate authenticated verification run in PostgreSQL
   created on 2026-11-01 (state WAITING_FOR_AUTHORIZATION). The temporary Redis
   pairing receipt expired, so the dashboard incorrectly showed no history.
2. Customer-host Gateway /health/live returned 200, but /health/ready returned
   GUARD_NOT_READY. Real Guard policy 8 is fresh but SharePoint source ACL
   health is false. Source certification is still absent.
3. The official SharePoint source is connected and ACL/directory syncs have
   been successful. Production has zero verified employee identity mappings
   and no signed effective-permission certificate for the SharePoint source.
   The Guard must fail closed, and the backend still has additional Protect
   evidence requirements.
4. Signed document content attestation and forgery rejection pass; this does
   NOT establish real employee effective access or authorization.

## Engineering fix
GET current application Gateway pairing now queries the existing tenant-scoped
durable VerificationRun only when the Redis status is missing/expired.
A historical installation is returned only if the current Guard and source
bindings match and the run is not superseded. The new state is explicitly
installation_reported_historical with live_gateway_verified=false and
production_certification=false. No new DB tables or migrations are required.
The UI labels it Previously installed, not live/healthy/certified.

No missing source certificates are manufactured, Guard policies are not
changed, and Protect stays pending until genuine tenant-specific evidence
and approval are available.

## Verified results
- Backend unit suite 670 passed (includes historical-pairing regression cases).
- Full Playwright suite 59 passed/5 skipped; targeted historical-state
  desktop/mobile regression 2 passed.
- Ruff, ESLint, TypeScript, Next.js build passed.
- Live customer-host original SharePoint RAG probe: documents=3, chunks=3,
  gateway_live=true, no direct model bypass, invalid employee identity closed,
  source_acl_healthy=false, identity mapping count=0, Protect not active.
- Cryptographic content binding, wrong-source and forged-content denial pass.

## Required provider actions before Protect can be marked active
- Alice and Bob independently sign into Microsoft Entra in the
  authorized synthetic tenant via device code.
- Delegated Microsoft Graph effective-file access tests and signed identity
  mapping evidence must match the expected Alice/Bob matrix.
- Genuine grant revoke/restore, stale cache, in-flight denial and signed
  Guard/Gateway Layer 1/2 challenge evidence must pass.
- An independent signer must issue a fresh tenant/source-bound effective
  permission certificate and the production SharePoint Protect provider scope
  must be explicitly enabled only after certification.
- Customer route cutover and Guard acknowledgment must be verified, without
  bypassing any missing evidence.
