# AccessProof — observed local system inventory (2026-10-20)

**Working tree:** `/home/white-devil/Downloads/accessproof/f15`; branch `master`; starting HEAD `ab59ffd`. Numerous pre-existing modified and untracked files; do not reset or commit them without review. Other local test processes and repository edits were observed during this run. This report describes the checkout, not a deployed binary.

## Components verified in source
- Control plane: `apps/api/accessproof_api/app.py`, `db.py`, `guard_pipeline.py`; FastAPI routes, auth and tenant management, SQLAlchemy, Alembic migrations.
- Customer Guard: `apps/guard/accessproof_guard/app.py`; local SQLite policy/decision/audit cache in `cache.py`; authenticated policy polling in `sync.py`; signed identity verification in `identity.py`.
- RAG: `packages/rag_sdk/protection.py` implements the buffered Python `ProtectedRAG` reference path: retrieved records → `/guard/v1/filter-resources` → model callback → trusted source trace → `/guard/v1/check-output` → response. `packages/rag_sdk/adapters.py` and TypeScript adapter package exist; complete third-party framework coverage is NOT established by existence.
- Google Drive: `connectors/google_drive/adapter.py` and `drive-rag-demo/app.py`; synced policy source can be stale. Current V1 objective is Google Drive + customer-owned custom RAG; Microsoft 365 code exists but is not a supported V1 claim.
- Background/deployment: `apps/worker`, `apps/runner`, Docker Compose files, Guard packaging, Redis, PostgreSQL, `web-v2`.
- Tests: pytest in `tests/`, UI Playwright, project Ruff/Mypy, Docker. Pytest requires `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` in the developer environment to avoid an installed unrelated ROS plugin conflict.

## Trust boundaries
1. Employee bearer JWT → Guard identity verifier; untrusted caller headers must not select identity/tenant.
2. Control-plane machine authentication → synchronized app bindings, source health, cache version and ACL decisions.
3. Customer retriever/metadata → Guard Layer 1. Only stable source/resource identity and explicitly allowlisted records enter the declared covered model callback.
4. RAG generation/tool/history → Guard Layer 2 using trusted orchestration provenance, prior authorization contexts, and release-time reauthorization. Model text and citations are not proof of their own provenance.
5. SDK returned `ProtectedResponse` → customer response writer: must enforce block and buffer. SDK cannot independently instrument a noncooperating application.
6. Independent tenant, source, principal, application and policy epochs must not share authorization state.

## Implemented vs unverified
- **Locally exercised:** synthetic JWTs, Guard HTTP routes, SDK Guard call sites, SQLite policy cache, revocation race, mode drift, safe deny, some API/control-plane tests.
- **Mocked:** source Drive ACLs, guard transport failures and model callbacks.
- **Not demonstrated here:** real Workspace ACL behavior, end-to-end production customer RAG tool/memory/stream instrumentation, independent OIDC/JWKS sandbox, p95/p99 under concurrent customer load, production recovery or real provider propagation lag.
- **No production actions:** no production tenant probing, new cloud deployment, or real customer credential use.
