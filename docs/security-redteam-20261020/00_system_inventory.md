# AccessProof verified inventory — synthetic red-team snapshot (2026-10-20)

**Original location:** /home/white-devil/Downloads/accessproof/f15 (dirty Git worktree; concurrent changes observed).
**Audited snapshot:** /tmp/accessproof-redteam-20261020/repo (separate, synthetic-only copy).
**No live rollout:** All patches described here are confined to the snapshot; no customer/production credentials or deployed services were changed.

## Verified components
- **Guard API:** `apps/guard/accessproof_guard/app.py`; token verification, per-application mode/source binding, Layer 1 filter and Layer 2 provenance-release gate.
- **Guard state:** `apps/guard/accessproof_guard/cache.py`; SQLite permission/version snapshot, health, in-flight decision contexts and audit buffering.
- **Guard synchronization:** `apps/guard/accessproof_guard/sync.py`; trusted control-plane snapshots and machine enrollment.
- **RAG SDK:** `packages/rag_sdk/protection.py`; `ProtectedRAG.run` buffers model output, authorizes sources and checks provenance.
- **Example customer RAG:** `drive-rag-demo/app.py` protected route, with synthetic tests.
- **Control plane:** `apps/api/accessproof_api` (FastAPI), PostgreSQL/Alembic, Redis/worker; actual production deployment not tested in this run.
- **Console:** `web-v2` (Next.js), browser tests with mocked endpoints.
- **Permission sources:** Google Drive V1 connector is the declared initial support target; Microsoft 365 code exists but real-provider support is not certified.
- **SDKs:** Python and TypeScript (`packages/rag-sdk-typescript`).

## Trust boundaries
1. Employee-supplied HTTP request -> verified bearer principal.
2. Customer-supplied retrieval metadata -> Guard source/file authorization.
3. Control-plane policy sync -> customer-side durable cache.
4. Guard Layer 1 response -> LLM context generation.
5. Model/tool/late-source provenance -> Guard Layer 2 release.
6. Guard enforcement -> customer HTTP/streaming adapter.
7. Tenant-admin management requests -> tenant-scoped control-plane storage and audit.

The Guard does not automatically secure uninstrumented RAG paths. Third-party RAG systems, live Google Workspace, actual JWT/JWKS issuer, and production availability are outside the tested snapshot.