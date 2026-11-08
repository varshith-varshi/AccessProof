# Certification status

Verified 2026-11-08T10:01Z via the restricted read-only SSM document `AccessProof-Certifier-ProductionReadOnly` (profile `accessproof-certifier`, not root).

## Route certificates (production)

| Org / app | Framework | State | Expires (UTC) | Last attested (UTC) | Recert due (≤48 h) |
|---|---|---|---|---|---|
| `48ee8c86…` / sharepoint-rag-staging | langchain | VALID (renewed early, 14/14) | **2026-11-15 09:57** | 2026-11-08 09:57 | early window from ~2026-11-11 |
| `48ee8c86…` / sharepoint-rag-staging | llamaindex | VALID (renewed early, 14/14) | **2026-11-15 09:25** | 2026-11-08 09:57 | early window from ~2026-11-11 |
| `48ee8c86…` / sharepoint-rag-staging | llamaindex (old) | INVALIDATED (superseded) | — | — | excluded from valid counts |
| `0fb98b25…` / pilot-hr-rag | langchain | VALID (renewed early, 14/14) | **2026-11-15 10:00** | 2026-11-08 10:00 | early window from ~2026-11-11 |

Status: CERTIFIED (signed by `ap-certifier-2026-11`, offline Ed25519 on the owner laptop).
**2026-11-11 expiry risk: RESOLVED** (F-001). Temporary SharePoint permission change, verified 10:01Z:
- the revocation recovery record is absent;
- Alice's direct read grant on the trial document exists again (read-only Graph check);
- the lab Guard and the pilot Guard both return ALLOW for Alice;
- each certification recorded `restored_allow_at`.

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
