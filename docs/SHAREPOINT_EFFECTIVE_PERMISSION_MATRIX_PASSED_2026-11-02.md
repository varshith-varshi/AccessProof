# Live Microsoft SharePoint effective-permission verification — 2026-11-02

**Verified synthetic permission matrix: 6 of 6 passed; 0 HTTP/permission errors.**

An authorized tenant administrator granted the AccessProof application
site-scoped FullControl on the synthetic AccessProof Validation 20261027
site through Microsoft Graph Explorer. Graph returned HTTP 201 Created.
This is not tenant-wide application permission.

Read-only AccessProof certificate-backed SharePoint REST probe:
- OAuth: correct tenant, SharePoint resource, Sites.Selected app role,
  certificate-authenticated appidacr=2.
- /_api/web: HTTP 200.
- Graph verified both synthetic employee immutable Entra object identities
  before resolving their SharePoint login claims.
- finance_alice.txt (list item 2): Alice ALLOW, Bob DENY.
- engineering_bob.txt (list item 3): Alice DENY, Bob ALLOW.
- shared_control.txt (list item 4): Alice ALLOW, Bob ALLOW.
- All six results matched the fixed, immutable synthetic oracle.

**No AccessProof source certification was issued.**
Production recheck after the successful test returned
certificate_verified=false, application_mode=protect_pending,
safe_to_enable_protect=false, and the original nine application-level
readiness blockers. The item-level test is a real provider observation,
but not yet persisted as an independently signed, expiring source
certificate or backed by interactive employee OIDC, revocation,
cache/provenance, Layer 1/2 route proof and customer cutover.

Do not infer successful production certification from these six results.
