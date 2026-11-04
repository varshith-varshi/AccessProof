# r35 live benchmark and technical certification (2026-11-04)

- **Production:** `r35-realtime-authz-a2f597312547` (commit `a2f5973`), deployed 10:39Z through `ship_via_ssm.sh`. Database `w7a8b9c0d1e2` unchanged; restricted roles kept; certifier trusted.
- **Notifications:** enabled 10:49Z (worker only; compose and `.env` backed up).
- **Lab:** Guard on r35; Gateway re-installed by the reference installer (r35).
- **Microsoft permissions:** **none added.** All three subscriptions (drive root, `/users`, `/groups/{id}/members`) were created with the app's existing permissions. Microsoft did **not** apply `Prefer: includesecuritywebhooks` (logged), yet it delivered notifications for every permission-only change tested.
- **Protect:** inactive.

## 1. Notification receipt → Guard enforcement (server-side, exact)
Source: production `provider_event_journal` joined to `guard.policy_installed` audit (`notification-journal-r35.csv`). n = 12 events with an install. All were processed on the first attempt: 0 retries, 0 dead letters.

| Stage | min | median | max |
|---|---|---|---|
| Receipt → worker picks it up | 0.26 s | 1.07 s | 1.72 s |
| Receipt → authoritative Microsoft re-read completed and policy committed | 3.52 s | 9.06 s | 10.60 s |
| **Receipt → Guard installed** | **4.40 s** | **9.89 s** | **11.35 s** |

- Group-membership (directory) events took 10.19 s and 11.35 s.
- With n = 12 a p95 is not statistically meaningful; the maximum (11.35 s) is reported instead. **Target "< 15 s p95": met in every sample.**
- Guard propagation after commit is about 0.3–1.1 s, against about 8 s for the policy plus about 12 s more for the revision on r34. This is the D-30 wake-up fix, measured live.

## 2. Source change → enforcement, live trials (harness-observed, seconds from the SharePoint change)
The harness samples every ~5–10 s through SSM, so these times include that sampling delay; section 1 is exact.

| Trial | Microsoft notification received (T2n) | **r35 first denial / allow** | r35 stable | **r30 polling first denial / allow** |
|---|---|---|---|---|
| A direct grant revoke | 32.8 | **56.2** | 117.4 | 83.3, 226.2 |
| A restore | 31.7 | **55.6** | 125.5 | 274.2, 243.9 |
| C inherited folder revoke | 33.6 | **56.8** | 126.7 | 40.4 |
| C restore | 33.4 | **44.7** | 107.4 | 263.6 |
| B **group membership** revoke | 26.7 | **40.4** | 111.3 | **430.6** |
| B restore | 40.7 | **56.3** | 120.8 | **843.0** |
| D deletion | 35.0 | **55.0** | 118.0 | 255.1 |

- **Microsoft delivery (change → notification):** 26.7–40.7 s, median 33.4 s, n = 7. That share is outside AccessProof's control.
- **Source change → Guard enforcement:** about 37–52 s (Microsoft delivery plus about 10 s for AccessProof). Under r34 polling it was 40–843 s, with group changes waiting for the directory cycle.
- "Stable" requires 5 consecutive denials spanning at least 60 s, so it is about 60 s after the first denial by definition.

## 3. Layer 1, Layer 2, cache and route on r35
- **Layer 1 Guard matrix:** 10/10, plus 8 controls: stale version, missing version, ID token and tampered signature, for each of Alice and Bob.
- **Protected RAG E2E-01…06, 10, 11:** 8/8.
- **In-flight revocation (Layer 2) and Gate E route challenge** (`route-certification-r35-b.json`):
  - Alice was revoked in SharePoint at 11:11:37.3.
  - The held request's Layer 1 ran at 11:12:00.3 and was allowed.
  - The Guard flipped at 11:12:21.7 (+44.3 s).
  - Layer 2 blocked with **`AUTHORIZATION_REVISION_CHANGED`**.
  - All four probes were correct. Control plane `tested_awaiting_customer_cutover`, **6 Guard audits matched**.
  - **Cutover verified** (`route-cutover-r35.json`, `customer_cutover_verified`).
  - A "hold first, revoke during the hold" barrier was also attempted. The Gateway's model timeout (30 s) is shorter than Microsoft delivery plus enforcement (about 40 s), so the held request returned 200 before detection. The agent correctly rejected that as not a revoke, and it is recorded.
- **Document freshness** (`document-update-freshness-r35.json`):
  - The Guard learned the new version **40 s** after the edit (about 5 min on r32), before the lab re-indexed (+3 min 26 s).
  - 9 stale-window samples: the old cached chunk was refused and **never reached the model**.
  - The document was served again at the new version. **PASS.**

## 4. Production security gates on r35 (11:27Z, certificate evidence supplied)
**A, B, C, D, E, F, G, H, I: PASS.** J fails only on `HUMAN_ACTIVATION_APPROVAL_REQUIRED` and `protect_acknowledged_by_guard`, the human step reserved for the owner (D-28).

## 5. Limitations (not hidden)
- **Microsoft's delivery time** (about 27–41 s here; documented maximum 6 h for driveItem; group/user unpublished) bounds detection. The 300 s polling and 900 s freshness fail-closed remain the safety net. No end-to-end SLO is claimed beyond what was measured.
- **The in-flight Layer 2 window** (between a request's Layer 1 and the Guard learning of a revocation) is therefore still about 40 s. Layer 2 blocks any response whose Layer 2 check runs after the Guard updates.
- **`includesecuritywebhooks` was not applied by Microsoft.** Permission-only changes still produced notifications in every trial, but that is observed behaviour, not a documented guarantee. Delta reconciliation covers any gap.
- **The source certificate expires 2026-11-11** and must be re-issued from fresh evidence. The r35 evidence above is eligible.
- **The lab model rarely quotes canaries** in response to the cutover's generic question, so cutovers needed several Guard-audited tries. This is a lab artifact, not a security behaviour.
