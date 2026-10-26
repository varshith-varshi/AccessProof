# Signed Redis answer cache in the supported Google Drive RAG reference route

**Scope:** This is a real, opt-in reference route integration, **not** an
automatic interceptor for arbitrary customer Redis instances, proprietary
model caches or other uninstrumented RAG endpoints.

The `drive-rag-demo` `/v1/protected-chat` path reads an answer cache only when
`ACCESSPROOF_DEMO_CACHE_URL` is explicitly configured. It requires
`ACCESSPROOF_DEMO_REQUIRE_ATTESTED_CONTENT=1`, a trusted ingestion public key,
an enrolled Guard, an application/source binding and `Protect` mode.

Private cache signing key configuration:

- `ACCESSPROOF_DEMO_CACHE_KEY_ID` — key identifier pinned by the trusted RAG
  service; manage rotation separately.
- `ACCESSPROOF_DEMO_CACHE_PRIVATE_KEY_B64` — base64-encoded, raw 32-byte Ed25519
  private seed. Keep it out of browsers, models, retrievers and version control.
- `ACCESSPROOF_DEMO_CACHE_URL` — tenant-controlled Redis endpoint; configure
  private networking/TLS, authentication, rate limits and availability.

**Cache write:** After a successful Layer 1 -> model -> Layer 2 decision, the
trusted reference RAG signs the exact answer and every source dependency,
including source-attested content digest, resource ID, chunk ID and version.
The cache stores a signed manifest alongside the answer with a 300-second
expiry. Missing or modified source attestations prevent writing.

**Cache read:** Every hit is re-verified cryptographically and passed through
both Guard layers for the **current requesting employee**. A revoked employee,
manifest tampering, missing dependencies, stale signature, cross-application
replay, oversized cache entry or unavailable Guard cannot release the old
answer. A rejected cache hit returns a denial and never falls back to an
unguarded cache or model regeneration. The existing source permission updates
must reach the Guard before denial; cache signatures alone are not instantaneous
provider revocation detection.

Only the documented employee-facing `/v1/protected-chat` route is covered.
The deliberately insecure legacy demo endpoint is disabled by default and is
never part of protected route certification. Customer applications must prove
all their alternate, batch, SSE, tool, memory, streaming and cache output paths
cannot bypass this protected route. The enterprise Gateway's separate strict
route is not automatically wired to this demo Redis cache; these are supported
reference integration patterns, not automatic universal protection.

The reference demo's regular file refresh still requires real trusted source
attestations to use signed cache mode; bare text documents from the legacy
fetcher are intentionally rejected. The private ingestion key stays separate
from the answer-cache signing key.

## Continuous customer-side trusted ingestion (reference deployment)

A separate `drive-rag-ingester` service signs a complete, bounded, fresh
snapshot. The RAG route only reads the already signed snapshot and holds the
source ingestion **public key**, never the private key or Google OAuth token.

1. Choose a customer-owned Google Drive folder with up to 50 indexed items
   and supported `text/plain` files and native Google Docs (exported as text). PDF/Office and other binary formats remain
   unsupported in this **reference** snapshot path; do not call this whole-
   Drive coverage. Shortcuts are excluded; if an item changes during fetch,
   the independent ingestion verification fails.
2. Generate a customer-side, mode `0600`, raw 32-byte Ed25519 private signing
   key, put it outside source control, and set
   `ACCESSPROOF_DEMO_SOURCE_SIGNING_KEY_PATH` to the absolute host file path.
   Publish only the corresponding public key in
   `ACCESSPROOF_DEMO_ATTESTATION_PUBLIC_KEY_B64` for the RAG container.
3. Place a `0600` Google OAuth credentials JSON file in the customer-owned
   `ACCESSPROOF_DEMO_GOOGLE_CREDENTIALS_DIR` (default: `.secrets`) as
   `token.json`; set `ACCESSPROOF_GOOGLE_DRIVE_CREDENTIALS_FILE` to
   `/run/secrets/google-oauth/token.json`. Fields required: `access_token`,
   `refresh_token`, `client_id`, `client_secret`, `expires_at` (timezone-aware
   ISO timestamp); optional: `scope`. The private ingester refreshes expiring
   tokens against Google's fixed token endpoint, persisting refresh-token
   rotation atomically with mode `0600`. If renewal fails, no new snapshot is
   published, and old attestations expire. Do not mount this file into RAG.
4. Set registered `ACCESSPROOF_DEMO_SOURCE_ID`,
   `ACCESSPROOF_DEMO_APPLICATION_ID`, and
   `ACCESSPROOF_DEMO_ATTESTATION_TENANT`. Provide the Guard endpoint and valid
   employee OIDC/JWKS authentication. To use the hardened reference overlay,
   start the customer-controlled stack with:

   `docker compose -f docker-compose.yml -f docker-compose.customer-signed-rag.yml --profile guard --profile drive-rag --profile drive-rag-ingest up -d --build`

   Review the generated Compose config and secrets first; run only within an
   explicitly approved customer/test environment. Do not assume the provided
   default development Guard setup is production hardened.
5. Check `/health/ready` on the reference RAG (not merely `/health`), run the
   positive/negative/revoke/cache/stream tests against synthetic employee
   accounts, and validate provider ACL sync and time-to-denial separately.
   `/health/ready` refuses stale/forged/missing snapshot, absent Guard, or
   unavailable configured cache. It cannot independently certify every
   upstream source permission or other customer application route.

Important: direct `DRIVE_OWNER_TOKEN`/manual unsigned Drive fetching is never
used by the **production** reference protected chat route. For production,
`ACCESSPROOF_DEMO_TRUSTED_SNAPSHOT_PATH` is mandatory. The default demo
`/v1/chat` remains disabled and should be blocked at network ingress.

### Disposable three-container end-to-end test

From the repository root, with Docker accessible and
`accessproof-drive-rag-audit:local` built:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/signed_reference_docker_smoke.py
```

It creates a disposable fake Guard + signed source + real Redis + reference
RAG route, checks first allow/cache hit/revoke-to-denial, and cleans up all
containers and its Docker network. This is *synthetic security evidence*, not
a real Google Workspace authorization or production latency measurement.
