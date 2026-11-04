# r35 production rollout runbook (owner-approved 2026-11-04)

Each step is independent and reversible. Run from the AccessProof repository on a workstation with AWS access to account 102076848988. Production instance: `i-0c11427d4d9c1b438`, region `eu-north-1`.

## 1. Deploy r35 (control plane: API, worker, web; no migration)
```bash
git fetch origin claude/realtime-authz
bash deploy/ec2-release/ship_via_ssm.sh a2f5973 w7a8b9c0d1e2 r35-realtime-authz
```
Expected: `DEPLOYMENT VERIFIED: api/worker/web on r35-realtime-authz-a2f5973…`. On any failure after migration the script rolls back on its own. Manual rollback:
```bash
sudo bash /home/ubuntu/accessproof-releases/r35-realtime-authz-a2f5973…/rollback_on_ec2.sh r35-realtime-authz-a2f5973…
```

## 2. Microsoft permission (Entra admin center)
For document-library notifications, grant the AccessProof app **`Files.ReadWrite.All` (Application)** and admin consent. Microsoft documents it as the minimum for driveItem subscriptions. Without it, drive changes stay on 300 s polling and group/user notifications still work.

## 3. Enable notifications on the worker
Copy `deploy/realtime/enable_microsoft_notifications.sh` to the host (SSM), then run:
```bash
sudo sh enable_microsoft_notifications.sh r35-realtime-authz-a2f5973…
```
It backs up the compose file and `.env`, edits the worker only, and restores both on failure. The worker creates subscriptions within about a minute. Check:
```sql
select channel_type, state, expires_at from provider_event_subscriptions where provider='microsoft365';
```
Logs `graph_subscription_create_failed … status=403` mean step 2 is still missing.

## 4. Lab Guard on r35 (customer side; the image is already built locally as `accessproof-guard-r35:a2f5973`)
Change the `accessproof-guard` image in `~/Downloads/sharepoint-rag-lab/docker-compose.accessproof-reference.yml`, recreate that service only, then re-stage the reference installation, because the compose bytes and therefore the deployment hash changed.

## 5. Phase 4 live certification
`scripts/live/revocation_trial.py` now records `t2n_notification_received` (first authenticated Microsoft notification after t0) separately from `t2_accessproof_detected`.
1. Run trials A, B, C, D and restore; then the RAG E2E, Layer 1 matrix, document-update freshness and route certification.
2. Run the production gates with the certificate evidence.
3. Re-issue the source certificate before 2026-11-11.
