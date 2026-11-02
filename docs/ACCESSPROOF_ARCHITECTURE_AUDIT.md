# AccessProof architecture audit (2026-11-02)

Scope: source code on branch `claude/modest-bell-tazupa`, based on
`origin/feature/real-customer-journey-r13` @ `6014a18` (the r19 snapshot) plus
the fixes in this change. This audit is a **code-level and local
service-boundary** review. The production hosts (`app.accessproof.in`,
`api.accessproof.in`, EC2 `i-0c11427d4d9c1b438`) and the synthetic SharePoint
tenant were **not reachable** from this engineering environment (see
"Environment limits" below), so nothing here is a statement about the live
deployment.

## Repository state found

| Item | Observed |
|---|---|
| Default branch `main` | `42df304` (2026-10-26), older Gateway-only V1 work |
| `feature/real-customer-journey-r13` | `6014a18` (2026-11-03 +0530, "r19"), **unrelated history** to `main`, 59 commits |
| `security/accessproof-source-published-20261027` | `d5f8471`, ancestor line of r13 |
| Working tree / other worktrees | clean, single worktree; no uncommitted work to preserve |
| Development branch | `claude/modest-bell-tazupa`, reset from `main` to r19 (it only contained `main`'s already-published history; nothing discarded) |

The local paths named in the brief (`/home/white-devil/...`) and any unfinished
local SharePoint certificate work do not exist in this environment and could
not be compared.

## Components (actual execution order)

```
SharePoint / Google Drive
   │  connectors/microsoft365, connectors/google_drive  (Graph/Drive APIs)
   ▼
Control-plane API  apps/api/accessproof_api/app.py  (FastAPI, PostgreSQL+RLS, Redis)
   │  acl_sync.py, directory_sync.py, authorization_revision.py,
   │  source_certification.py (Microsoft eligibility gate),
   │  gateway_pairing.py (Redis, one-use), verification_engine.py,
   │  gateway_presence.py (NEW, D-02)
   │  GET /api/v1/guards/{id}/policies  ── machine-authenticated sync
   ▼
Customer-hosted Guard  apps/guard/accessproof_guard/app.py  (SQLite policy cache)
   │  /guard/v1/filter-resources  = Layer 1
   │  /guard/v1/check-output      = Layer 2
   │  /health?application_id=     = per-application readiness
   ▼
Customer-hosted Gateway  apps/gateway/accessproof_gateway/app.py
   │  verifies Ed25519 ingestion attestations (packages/rag_core/attestation.py)
   │  ProtectedRAG.run (packages/rag_core/protection.py):
   │    L1 filter → verify signed bytes → build context from allow-list only
   │    → ONE buffered model call → trace completeness → late-source L1
   │    → L2 check → revision equality L1==L2 → release
   ▼
Customer RAG → model (OpenAI-compatible / Anthropic / Gemini adapters)
```

The real data path matches the intended two-layer design: unauthorized chunks
are removed **before** the model call and model context is assembled only from
the Guard allow-list after signature verification (`GatewayService.protected_chat`).
Streaming is synthesized from a fully verified buffered answer
(`completion_response`), so no model byte reaches the employee before Layer 2.

## Trust boundaries

| Boundary | Mechanism | Notes |
|---|---|---|
| Employee → Gateway/Guard | Bearer OIDC JWT verified by Guard (`identity.py`), issuer/audience/tenant/exp/signature; `sub`/`oid` only | Static HS256 mode now **refused in production** (D-03) |
| Guard ↔ control plane | Per-Guard machine credential (hash stored), monotonic presence sequence | Policy sync is pull-only |
| Gateway ↔ control plane | One-use 15-min pairing token (Redis) → **durable per-installation credential** (D-02) | Heartbeat is not Protect evidence |
| Ingestion → Gateway | Ed25519 attestations over exact chunk bytes, pinned public keys | Forged/altered bytes rejected before generation |
| Certifier → API | **Ed25519, public key only in API** (D-01) | Previously HMAC with the key inside the API |
| Tenant isolation | PostgreSQL forced RLS on tenant tables + explicit `organization_id` predicates | New `gateway_installations` table has forced RLS |

## Root cause of the reported live failures (from code)

1. **Guard `DEGRADED`, `source_acl_healthy=false` for SharePoint.**
   `guard_policies()` → `source_acl_healthy()` returns `False` for any
   Microsoft source unless `effective_source_certified()` passes. Production
   holds zero certificates (per `docs/PRODUCTION_API_R2_SHAREPOINT_CERT_2026-11-01.md`).
   This is correct fail-closed behaviour, **not a bug to override**. The
   missing input is an independently issued certificate backed by live
   evidence (employee OIDC, revoke/restore, protected-route tests).
2. **Gateway `/health/ready` 503 `GUARD_NOT_READY`.** The Gateway asks Guard
   `/health?application_id=…`; Guard reports not ready because of (1). Correct.
3. **Protected answer 503.** `_application_mode` raises `SOURCE_ACL_STALE`
   for the same reason. Correct.
4. **"Previously installed" shown without liveness.** There was no Gateway
   heartbeat at all. Fixed by D-02.

Making (1)–(3) green requires real tenant work that cannot be done from
code; see `ACCESSPROOF_PRODUCTION_READINESS.md`.

## Environment limits of this audit

* Outbound HTTPS to `app.accessproof.in` and `api.accessproof.in` was denied
  by the session's network policy (proxy CONNECT 403).
* The AWS credentials present in the container were rejected by STS
  (`InvalidClientTokenId`); EC2/SSM inspection was not possible.
* No Microsoft tenant credentials, employee accounts, customer host or
  `sharepoint-rag-lab` checkout were available.

All results in this change are therefore local and synthetic.
