# SharePoint validation-first Protect (2026-11-07)

## Product decision

An **independent SharePoint source certificate is not required before the
first explicit activation request** for a newly connected, eligible SharePoint
source. A customer may activate enforcement first and **then** manually test
the chatbot with approved synthetic documents and two test identities.

This changes the activation *order*, not the Guard's authorization decisions.
Signed source certification remains available after validation as independent
proof; the dashboard must never describe a not-yet-certified source as
`PROTECTED_VERIFIED`.

## Fail-closed prerequisites that remain mandatory

- Source is **SharePoint list-item effective** profile, not arbitrary OneDrive,
  an ambiguous Microsoft drive, or an unrecognized provider.
- Production Microsoft source release is enabled; the feature is restricted
  to sources **never certified before**. Once a source has any certificate row,
  expiration, revocation, signing failures or scope changes block Protect.
- Source connected and validated, encrypted credentials readable.
- ACL **and** directory synchronization fresh and free of errors.
- No unresolved permission events or pending policy distribution.
- Two distinct immutable Entra OID identities mapped `directory_verified`
  to this exact organization/source/tenant.
- Enrolled non-revoked Guard, fresh heartbeat, installed policy, OIDC issuer/
  audience configuration, signed authorization revisions and audit buffering.
- Authenticated Gateway heartbeat indicating enforcement readiness, tied to
  the exact application/Guard/source.
- Explicit signed-in Owner/Admin `Enable Protection` request. API keys,
  onboarding receipts, pairing alone and Guard heartbeats cannot authorize it.

## Two-phase activation handshake

1. Owner/Admin explicitly clicks **Enable Protection**.
2. If all source and policy prerequisites pass but initial
   `PRODUCTION_OIDC_READY` or `GATEWAY_LIVE_AND_ENFORCEMENT_READY` lags,
   the backend sets **protect_pending** and a bound
   `ProtectionActivationRun.awaiting_guard_ack`.
3. The Guard receives the pending binding; its app-specific source health
   checks now use live ACL/directory freshness rather than the missing
   first-time certificate. The Gateway rechecks the Guard and reports
   authenticated readiness.
4. The Guard's machine acknowledgment activates Protect **only after all
   required checks pass**. If anything stays unhealthy, Protect remains pending.
5. The dashboard shows `PROTECTED_MANUAL_VALIDATION_PENDING` until
   independent source and route evidence is complete. Test allowed, denied,
   revoked and cached access with synthetic documents before relying on
   real confidential data.

## Runtime safety

- Guard continues to enforce JWT/OIDC signatures and exact immutable mapping,
  document- and version-specific Layer 1 decisions, and Layer 2 provenance
  and authorization before answer release. Missing evidence is denied.
- A source with a previously issued but expired/revoked/tampered certificate
  can **never** use this first-time exception.
- This change does not grant Microsoft site permissions, issue fake signatures,
  disable audit or permit arbitrary RAG paths.
- The feature may be disabled independently using
  `ACCESSPROOF_MICROSOFT_VALIDATION_FIRST_PROTECT_ENABLED=0`.
- `ACCESSPROOF_MICROSOFT_CERTIFIED_PROTECT_ENABLED` must remain enabled
  for the reviewed SharePoint profile release. Neither switch alone grants
  access without the other runtime checks.

## Validation status

Automated code and synthetic test coverage are not substitutes for real
customer human validation. A Guard/Gateway healthy heartbeat is proof of
connectivity/enforcement configuration, **not** an independent provider-live
certificate. Record any failed allow/deny/revoke tests and disable Protect
until corrected.
