# Release r37: Universal RAG + continuous trusted-ingestion refresh

Release branch: `claude/universal-rag`. Code freeze: `388238b`. Production is currently running r35 (`a2f5973`). The previous safe release, r35, is the rollback target.

## Components changed (vs production r35 `a2f5973`)

| Component | Change | Where it runs |
|---|---|---|
| Control plane (api/worker) | D-31 fix: no new authorization revision on a no-op sync (`acl_sync`, `directory_sync`) | production |
| Control plane (api) | Source certificate validity raised to at most 30 days (was 14). Adds the owner-only route `/api/v1/current/sources/{id}/certificate/revoke`. | production |
| Database | **No migrations** | none |
| Gateway | Remote exposure (TLS, ap-req-v1 application signatures, replay/rate limits). Signed hash-chained audit log. `POST /v1/evidence/manifest`. All default **off**; local mode is unchanged. | customer |
| `accessproof-rag` client | Stdlib client, LangChain and LlamaIndex adapters, `EvidenceSubscriber` | customer RAG host |
| Trusted ingestion | `packages/rag_core/evidence_{manifest,refresher}.py`: signed manifests, continuous refresh | customer ingestion environment |
| Route certification | `remote_route_certification` (14 evidence-backed checks, binding invalidation) | certifier |

## Test results (evidence: `docs/evidence/evidence-refresh-2026-11-04/`, `docs/evidence/universal-rag-2026-11-04/`)

| Suite | Result |
|---|---|
| SQLite full regression (`860d296`) | 1638 tests, 0 failures, 0 errors |
| PostgreSQL full regression, least-privilege roles (`860d296`) | 1638 tests, 0 failures, 0 errors |
| Portable client suite (`388238b`) | 7/7 |
| 100-minute live soak (real SharePoint, Entra, Guard, remote TLS Gateway) | **PASS.** 23 refresh cycles, 0 refresher failures. Bob's finance requests reached the model 0 times in 91 samples. 12/12 scenarios pass (offline restart passes after fix `388238b`). |
| Remote route certification, LangChain (continuous subscription) | **CERTIFIED 14/14** (lab certifier key) |
| Remote route certification, LlamaIndex (continuous subscription) | **CERTIFIED 14/14** (lab certifier key) |

## Known limitations

- Remote route certificates are signed by a lab key and are **not enforced by the production control plane**.
- Windows was NOT TESTED. Physical cross-host was BLOCKED (the tunnel needs approval). The lab used separate network namespaces on one host.
- r36b is not yet deployed, so production still shows D-31 revision churn and accepts at most 14-day certificates.
- The `/proc` bypass probe can't observe Windows RAG hosts, so they can't be certified (this fails closed).

## Rollback

Control plane: `bash deploy/ec2-release/rollback_on_ec2.sh` (via SSM) back to r35, `/home/ubuntu/accessproof-releases/r35-realtime-authz-a2f597312547`. No schema change, so the database is untouched. Customer-side components are opt-in: unset `ACCESSPROOF_GATEWAY_EXPOSURE`, `_AUDIT_*` and `_EVIDENCE_*` to return the Gateway to local mode.
