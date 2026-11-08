# Independent certificate renewal: authorized cutover gates

**CURRENT: NOT ACTIVE.** The existing private EC2 certifier stack is deployed; read-only watcher is in place. This checklist cannot replace Owner approval or live evidence.

## Facts and restrictions

- The dedicated certifier EC2 reported in previous operator evidence is `i-0af8a03948e7ba058`, with CloudFormation stack `accessproof-independent-certifier-2026` in `UPDATE_COMPLETE`. Reverify before any mutation.
- The dedicated Ed25519 KMS signer has a distinct key ARN. Never export its private key, copy the laptop's old signing key, reuse the backup-encryption KMS key, or generate a replacement simply because the existing role lacks access.
- The certifier profile `accessproof-certifier` does **not** have `kms:GetPublicKey` from this laptop; a read-only attempt on 2026-11-08 returned `AccessDenied`. The private instance's purpose-bound execution role may differ. Do not use root to override the boundary.
- During continuation the non-root infrastructure profile's AWS login session expired; obtain a fresh authenticated session from the authorized administrator before repeating live preflights.
- The owner-laptop source renewers and route-attestation timers are still the only authorized certificate writers. They must remain enabled until independent renewal is demonstrated with the laptop offline.

## Review gate 1 — infrastructure and trust (no signatures)

1. Confirm the existing CloudFormation stack, exact host IAM role, KMS key, pinned Ed25519 `GetPublicKey` metadata and restricted read-only watcher.
2. Export the new **public** key only through the purpose-bound reviewed exporter using an authorized role, then independently approve a distinct key ID and dual-key trust registration in the production API.
3. Verify old certificates remain valid and unknown signatures fail; confirm rejected rollback/replay/cross-tenant certificate cases before accepting new trust.
4. Complete a reviewed, reversible release through the existing scoped production deployer. No trust write occurs merely because KMS returns a public key.

## Review gate 2 — strictly scoped new signing and evidence import

1. Approve a narrowly scoped IAM grant for `kms:Sign` with `SigningAlgorithm=ED25519_SHA_512` on the **exact reviewed signing key**. No generic SSM shell, wildcard KMS, role creation, unrestricted production import, AWS root or static credentials.
2. Permit only the pinned, reviewable SSM ProductionReadOnly, ProductionImport and approved route-probe operations for the intended production app/source scopes.
3. Preserve immutable evidence and two-person audit/reviewer gating; certificate generation must fail if required current live observations are absent.

## Review gate 3 — customer/employee consent and independent Guard path

1. Alice and Bob must genuinely authorize delegated Microsoft Entra employee sessions on the dedicated independent host, using an approved token lifecycle and secret store. Never copy existing laptop token sockets or refresh credentials.
2. Customer Owner/Admin approves an always-on private Gateway/Guard/RAG route that is independent of localhost SSH tunnels on the laptop. Require end-to-end TLS, route digest, Guard application binding and current SharePoint authorization.
3. Complete fresh permission, revocation, cached-answer, tamper and signed-route challenges on the actual customer-approved route.

## Review gate 4 — witnessed automatic renewal and rollback

1. Issue/verify/import an actual KMS-signed certificate from the independent host using fresh evidence; compare resulting production state, signature key ID and expiry. Never simply extend DB expiry.
2. Exercise failure modes: signer denied, expired employee session, Guard offline, network loss, wrong key, stale evidence, replay, revoked identity and partial import. Confirm fail-closed behavior.
3. Simulate or witness the owner's laptop being **offline** while the independent host completes a new authorized renewal and the customer-approved RAG route remains reachable. Do not shut down the laptop without express user permission.
4. Verify alerting, rotation/rollback and reviewer sign-off. **Only then** migrate ownership of active certificate writing and disable laptop renewal timers.

## Clear end states

- Read-only watcher healthy: `MONITORING_ONLY`, not auto-renewal.
- KMS public key exported but no trust/sign rights: `CUTOVER_PENDING_APPROVAL`.
- App source certificate in date but route still depends on laptop: `NOT_INDEPENDENT`.
- Genuine off-laptop signed/imported renewal plus customer route and Alice/Bob authorization: `INDEPENDENT_RENEWAL_VERIFIED`.

The current product must not be represented as generally available merely because the existing technical pilot routes passed their last challenge.
