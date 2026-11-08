# Certification status

Verified 2026-11-08T08:50Z via the restricted read-only SSM document `AccessProof-Certifier-ProductionReadOnly` (profile `accessproof-certifier`, not root).

## Route certificates (production)

| Org / app | Framework | State | Expires (UTC) | Last attested (UTC) | Recert due (≤48 h) |
|---|---|---|---|---|---|
| `48ee8c86…` / sharepoint-rag-staging | langchain | VALID | 2026-11-11 17:02 | 2026-11-08 05:31 | 2026-11-09 17:27 timer run |
| `48ee8c86…` / sharepoint-rag-staging | llamaindex | VALID | 2026-11-11 19:00 | 2026-11-08 05:32 | 2026-11-10 05:27 timer run |
| `48ee8c86…` / sharepoint-rag-staging | llamaindex (old) | INVALIDATED (superseded) | — | — | excluded from valid counts |
| `0fb98b25…` / pilot-hr-rag | langchain | VALID | 2026-11-11 18:02 | 2026-11-08 05:32 | 2026-11-10 05:27 timer run |

Status: CERTIFIED (signed by `ap-certifier-2026-11`, offline Ed25519 on the owner laptop).
**Expiry risk: P0, see FINDINGS F-001.** Recertification needs live Alice and Bob sessions. With F-001b, one sign-in using `AP_RECERTIFY_AFTER_SIGNIN=1` recertifies all three routes immediately, because they are within the 4-day early window. The mandatory ≤2-day timer path remains as a fallback.

## Source certificates

| Org / source | State | Days remaining | Expires | Renewal window opens |
|---|---|---|---|---|
| pilot `0fb98b25…` / `4eb6863f…` | OK (verified) | 26.56 | 2026-12-04 | ~2026-11-24 |
| reference `48ee8c86…` / `2fa9562b…` | OK (verified) | 26.30 | 2026-12-04 | ~2026-11-24 |

The source renewal (`accessproof-cert-renewal{,-pilot}.timer`) also needs the Alice and Bob sessions. The same owner action is needed again around 2026-11-24.

## Signing keys

| Key | Location | Production trust | Signing |
|---|---|---|---|
| `ap-certifier-2026-11` | owner laptop, 0600 PEM | trusted (pinned) | active (laptop timers) |
| `kms-certifier-2026-11` (KMS `0f040c1c…`, ED25519, Enabled) | AWS KMS eu-north-1 | **not registered** | **disabled** (kms:Sign denied to the execution role) |

No trust change was made this session. A KMS trust transition requires owner authorization: register the new key alongside the old one, test rejection and rollback, then grant `kms:Sign`.

## Renewal automation

| Unit (owner laptop, user systemd) | State | Last result |
|---|---|---|
| accessproof-route-attestation.timer | active (next 17:23Z ± 10 min) | 2026-11-08 05:32Z OK (3/3). Now also runs early recertification when sessions cover a full run |
| accessproof-cert-renewal{,-pilot}.timer | active | daily; window not yet open |
| accessproof-renewal-watchdog.timer | active | WARNING (expected: WATCH + new EMPLOYEE_SESSION_LIFETIME_UNKNOWN) |
| accessproof-source-expiry-monitor.timer | active | OK |
| Independent EC2 status watcher | active (per 2026-11-08 rollout doc) | observes only; cannot renew |
