# Gateway validation (2026-11-02)

## Enforcement path (reviewed in code)

`POST /v1/chat/completions` → bearer token required before body parse →
strict schema (`extra=forbid`) → application binding check →
`ProtectedRAG.run`:

1. Guard Layer 1 on retrieved resources (deny → 403 `NO_AUTHORIZED_RESOURCES`).
2. Ed25519 verification of every authorized chunk **before** generation.
3. Model context built only from the allow-list; one model call, buffered,
   byte-bounded.
4. Trace completeness (every generator input present with identical bytes).
5. Late sources get their own Layer 1.
6. Guard Layer 2; Layer 1 and Layer 2 authorization revisions must be equal.
7. Release. `stream=true` emits SSE only from the verified buffer.

Any exception → `block` (`PROTECTION_PIPELINE_FAILED` / `GUARD_REQUEST_FAILED`).
Guard unavailable → `/health/ready` 503 and requests fail closed.

## New: authenticated liveness (D-02)

| Signal | Meaning | Source |
|---|---|---|
| `installation_reported_*` | an installer once claimed a pairing | Redis / durable verification run |
| `gateway_connectivity.connection = CONNECTED` | this installation's credential sent a non-replayed heartbeat within 35 s (server clock) | `gateway_installations` |
| `enforcement_ready_reported` | on that heartbeat the Gateway's own `/health/ready` passed | Gateway-reported |
| Protect active | every activation check passed and Guard acknowledged | unchanged |

Configuration (written by the installer into `gateway-presence.env`, 0600):
`ACCESSPROOF_GATEWAY_PRESENCE_{CONTROL_PLANE_URL,ORGANIZATION_ID,INSTALLATION_ID,CREDENTIAL,ROUTE_SHA256}`,
optional `…_INTERVAL_SECONDS` (2–60, default 10). The API setting is
`ACCESSPROOF_GATEWAY_OFFLINE_SECONDS` (default 35).

## Tests

`tests/integration/test_gateway_presence.py` covers fresh/ready, connected but
not ready, replay (equal and older), forged credential, cross-tenant
credential, wrong organization, wrong application, route change, heartbeat
expiry, Guard rebinding, credential rotation, legacy UNKNOWN, the activation
gate, the real Gateway reporter against the real API route, plaintext refusal,
and the 0600 env file with rotation. The existing ~40 Gateway test files still pass.

## Not validated here

The installer's `docker compose up --force-recreate` step on a real
customer host. It is behind the same approval flow as the install, but was not
executed in this environment (no Docker daemon or customer stack).
