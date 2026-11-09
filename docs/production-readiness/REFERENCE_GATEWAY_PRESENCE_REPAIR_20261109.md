# Reference Gateway — owner-authorized heartbeat and route renewal

**Evidence date:** 2026-11-09. **Status:** BLOCKED ON FRESH OWNER/ADMIN PAIRING AND LIVE ROUTE CHALLENGE. No credential, certificate or customer Protect status was altered.

## What passed

Read-only command:

```bash
cd /home/white-devil/Projects/AccessProof-universal
.venv/bin/python scripts/drills/reference_gateway_presence_preflight.py \
  --pairing-file "$HOME/Downloads/accessproof-gateway-pairing.json"
```

The output is sanitized. Current live evidence:

- Exactly **one selected Gateway**: `ap-remote-gateway`.
- Image ID pinned to `sha256:d2f3db8e7be57504fbbdb183cae8c5a9586a5c322788d766a2f027b46fd47219`.
- Correct reference org `48ee8c86-d4d8-4cde-b00b-bc779f965f4f` and app `sharepoint-rag-staging`.
- Verified pinned certificate and hostname via `~/.ap-id/remote-gw/ca.pem` on `https://ap-gateway.lab.internal:8443/health/ready`: HTTP 200.
- Published only on `127.0.0.1:8443`; existing private Guard/edge networks present.
- Read-only filesystem, ALL Linux capabilities dropped and `no-new-privileges` configured.
- The running image **already contains authenticated presence reporter code** in `/app/apps/gateway/accessproof_gateway/presence.py` and its app startup. No backend feature rewrite is required to send heartbeats.

## Why it cannot be marked connected

- **None** of the five `ACCESSPROOF_GATEWAY_PRESENCE_*` settings are present on this exact runtime.
- `ap-remote-gateway` is a legacy manually started (non-Compose) HTTPS Gateway.
- Previous saved `gateway-presence.env` files were issued for a different staged 8191 route, **not** this exact HTTPS 8443 route. Reusing them would fabricate a route-presence binding.
- The latest downloaded `accessproof-gateway-pairing.json` fails reference application/tenant scope validation. Older pairings have expired. No usable fresh one-use reference pairing exists.
- Production read-only SSM `7a0faa28-f726-4bde-9ce7-2e4dd7edfd51` returned `gateway_presence.connection=DISCONNECTED`, reason `HEARTBEAT_EXPIRED`, and application-route certificate `EXPIRED`. Two older remote reference route certificates can remain `VALID` without fixing the application-specific certificate.

## Required next action by authenticated reference Owner/Admin

1. Sign in to `https://app.accessproof.in`, switch to the **reference** organization that owns `sharepoint-rag-staging`.
2. Open **AI applications → sharepoint-rag-staging → Gateway pairing / Connect RAG**, and request a **fresh one-use pairing file** for that exact app.
3. Save it **privately on the authorized laptop** (mode 0600; never paste token into chat or logs). It expires in 15 minutes.
4. Approve migration of **only** `ap-remote-gateway` from the manual launch to a reviewed supported deployment for the **same exact TLS 8443 route**, image/source/Guard binding, audit mounts and private networks. The old 8191 installer configuration or another synthetic organization's Gateway is not an eligible replacement.
5. After fresh pairing, the reviewed migration must bind the server-issued `gateway_presence` installation ID, credential, organization, app and **actual HTTPS route digest** to this Gateway, then restart **only this Gateway** with rollback; do not change the Guard, RAG or other app.
6. Verify production API observes a **fresh, replay-protected authenticated** heartbeat with `connection=CONNECTED` and `enforcement_ready_reported=true`. A local HTTP 200 or pairing receipt is **not** proof.
7. Issue a new actual application-route challenge using authorized Alice/Bob Entra sessions and observed real Guard/Gateway allow, deny, tamper and revocation behavior. Submit machine-bound signed evidence and complete genuine customer-route cutover. Require the API to return a new `CERTIFIED` application-route certificate with an actual expiry. Never extend the expiry directly in SQL or disable readiness checks.
8. Keep pilot route and customer traffic fail-closed throughout. On failure, roll back only the reference Gateway, invalidate an unused pairing and report `NOT_CERTIFIED`.

## Still separate from independent renewal

Even a repaired reference heartbeat on the owner's laptop cannot make route renewal laptop-independent. The certified Gateway/Guard/RAG route must be placed on an authorized **always-on host**, and real delegated Entra sessions, trusted KMS sign/import permissions, and an off-laptop renewal test remain necessary. Do not copy old Microsoft refresh tokens, private signing keys, or obsolete Gateway credential files to AWS.

**Do not claim completion** until production itself reports `CONNECTED` and `CERTIFIED` from fresh verified evidence.
