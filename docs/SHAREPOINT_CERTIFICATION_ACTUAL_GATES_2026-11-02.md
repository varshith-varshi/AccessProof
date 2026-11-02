# Live SharePoint certification continuation — 2026-11-02

**Current state: NOT_CERTIFIED / Protect remains blocked.**

## Independently completed

- Certificate-backed SharePoint REST effective permission matrix: all 6 of 6
  tests passed against the live approved validation site (Alice/Bob; three
  synthetic SharePoint files). Zero HTTP or permission errors.
- Existing native Graph sharing grants match the expected synthetic matrix.
- Real indexed content carries a valid Ed25519 attestation verified against
  Gateway-pinned public key; altered bytes and wrong source ID are rejected.
- Existing negative Gateway test blocks invalid identities and releases no
  signed customer content. This alone does not establish positive/negative
  employee-authenticated Layer 1/Layer 2 enforcement or cryptographic
  provenance checks on an actual positive model result.
- Existing unit/integration suite for SharePoint permission provider/release
  and Guard negative controls passed.
- A new hardened operator-scoped synthetic revoke-and-restore test is
  implemented at scripts/sharepoint_synthetic_revocation_trial.py, with
  read-only default, explicit application authorization flag, strict single
  synthetic file and principal scope, an on-disk 0600 recovery record,
  restoration in finally, and restore-only recovery mode. Live dry run
  passed without modifying a single SharePoint ACL. Its exact target is
  finance_alice.txt at the approved synthetic site, list item 2.
- The new script passes Ruff, Mypy and focused security regression tests.

## Genuine dependencies before certification

- Alice and Bob MUST each authenticate via real Microsoft Entra login as
  distinct test employees. App-only Graph object mapping does not replace
  employee OIDC signature and delegated content access.
- Once the initial signed-identity baseline is captured, an authorized
  narrowly scoped revoke-and-restore test must show that the provider's
  *effective* rights actually change, not just Graph sharing records.
- Independently challenge the connected customer RAG/Gateway with accepted
  employee tokens on a positive route, negative route, in-flight revoke,
  expired/revoked policy, response buffering, cache hit, and provenance tamper.
  Current Guard is degraded because source ACL is uncertified, and its
  policy reports 0 verified OIDC mappings.
- Verification results must be scoped, independently verified, signed by
  the operator-managed certification key and persisted in the source
  certification table with short expiry. A source certificate may be
  issued ONLY when all required source checks are passed. A live permission
  matrix alone cannot authorize Protect.
- Customer-approved final route cutover is a separate explicit gate.
  Never force Protect, fabricate evidence, remove Microsoft security controls,
  or infer readiness from Docker/heartbeat health.

## Live diagnostics

- Existing RAG: three signed documents and three chunks indexed; Gateway
  live, but its ready path is blocked by GUARD_NOT_READY.
- App mode remains protect_pending on control plane. Local policy describes
  protect mode but source_acl_healthy=False and Guard not globally ready.
- Production ready API HTTP 200 and r11 worker active, but source effective
  certificate count=0 and the durable verification run is
  WAITING_FOR_AUTHORIZATION.

## Operator workflow when employee consent is ready

- Run one real employee login at a time:
  python scripts/verify_delegated_actors.py --actor alice
  python scripts/verify_delegated_actors.py --actor bob
  from the existing sharepoint-rag-lab root with the correct Python
  environment. Device codes require each real employee's interactive sign-in.
- Before changing any grants, use from the AccessProof repo:
  python scripts/sharepoint_synthetic_revocation_trial.py
- On explicit authorization of the synthetic reversible revocation:
  python scripts/sharepoint_synthetic_revocation_trial.py
    --execute --acknowledge-synthetic
- If interrupted and recovery file remains:
  python scripts/sharepoint_synthetic_revocation_trial.py --restore-only
  Do not proceed with any other test until restoration has been verified.
- Recheck all 6 original permissions and provider source readiness. Then
  execute protected route challenges and only afterwards consider issuing
  an independent source certificate.

DO NOT copy tenant access tokens, private keys or employee passwords into
Git or user-visible logs. All real OAuth tokens remain in RAM.
