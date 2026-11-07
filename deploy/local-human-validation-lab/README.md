# AccessProof local Human Validation — startup recovery reference

**Lab-only. Not an always-on customer deployment and not a certification issuer.**

This folder preserves the source used by the local SharePoint Human Validation
RAG. The live instance runs separately from
`~/Downloads/accessproof-human-validation-rag` on the approved Ubuntu test
host; the code here is not automatically deployed when the repository changes.
Do not copy private `.env`, private signing PEMs, employee OAuth sessions or
Gateway installer credentials into Git.

## Normal startup

Docker and Ollama start through their enabled system services. The customer
Guard, Gateway, RAG, Redis, ingester, and model bridge containers all use
`restart: unless-stopped`. The user has systemd lingering enabled, so the
`accessproof-local-ollama-bridge.service` starts even without a desktop login.

The `accessproof-human-validation-recovery.timer` starts after the user manager
boots and checks every two minutes. Its oneshot service can start only the
explicitly named **existing** containers. Missing installations are reported
rather than automatically reconstructed. If the signed index is stale or
invalid, the service may restart only the separate **trusted SharePoint
ingester**, with a four-minute cooldown. No Guard policy or authorization
fallback is ever enabled.

The recovery controller stores a mode-0600 JSON report at
`~/.config/accessproof/human-validation-recovery/latest.json`. To check
read-only health:

```bash
python3 ~/Downloads/accessproof-human-validation-rag/scripts/recover_lab.py --check
systemctl --user status accessproof-human-validation-recovery.timer
docker ps --format '{{.Names}} {{.Status}}'
curl --fail http://127.0.0.1:28189/health/ready
```

**Do not reboot the laptop for these checks without its owner's approval.**

## Signed-content readiness and isolation

An ingester with trusted Graph credentials, provider egress and the private
Ed25519 signing key periodically re-fetches synthetic SharePoint documents,
signs exact bytes and atomically replaces the index. The ingester Docker
healthcheck requires a recent sync. The RAG Docker healthcheck, its
`/health/ready` endpoint, and each protected question require all signed
index chunks to be fresh, signed by a pinned public key, and bound to the exact
tenant/source/application/item/version/bytes. No near-expiry tokens are
accepted. The Gateway independently performs the final signed-content,
Layer 1 and Layer 2 verification.

**The RAG must receive only public configuration**, in a mode-0600
`.env.rag` file: `LAB_TENANT_ID`, `LAB_APPLICATION_ID`, `LAB_SOURCE_ID`,
`LAB_ENABLE_BASELINE=0` and `LAB_SOURCE_PUBLIC_KEYS_JSON`. Its source
public key should be matched to the Gateway verifier and the trusted
ingester's signer before onboarding. The original `.env` file with
SharePoint Graph credentials belongs to the `ingest` service only.

All confidential test-document content remains in the private customer RAG
index; the Alice/Bob operator console uses memory-only real Microsoft Entra
sessions, no password or bearer token storage in the browser. After a
shutdown, each employee may need to sign in again.

The local Ollama model bridge is pinned to the known model and host-only
network path. Local endpoints do not themselves establish production
certification or continuous availability when the laptop is powered off.

## Installation constraints

The live installation has reviewed Guard/Gateway installer manifests and
separately provisioned source credentials. This reference deliberately omits
those assets. Reinstalling from this folder **requires** a new, authorized
customer onboarding and signed Gateway pairing. Never invent manifests,
keys, Microsoft identities or certificate evidence to make health green.
Use the installer for Guard/Gateway rather than spinning up an unsigned
replacement.

To install the recovery check on an already approved host, adapt the
`systemd/*.service` paths to that host's verified install location, then
load the user units and enable the timer. Do not use this example to bypass
a production security gate.

## Verified 2026-11-07

- Synthetic attestation and recovery tests: 16/16 passed.
- Live local deployment: RAG and ingester Docker health healthy; five signed
  SharePoint chunks with freshly verified signatures; Guard policy 14 and
  Gateway ready. RAG container no longer receives SharePoint client secret.
- Controlled *ingester-only stop/start* recovery: passed; trusted Graph sync
  resumed, signed-index health returned, Guard/Gateway remained ready.
- Prior real Microsoft Entra Alice/Bob permission matrix: 10/10, with
  independent SharePoint effective-permission matrix 10/10. Additional
  token-based matrix after this recovery release still requires an actual
  employee session and was not repeated via an automated terminal check.
- **Not performed:** an actual Ubuntu reboot; production always-on host
  migration; live revoke/restore; independent source certification.
