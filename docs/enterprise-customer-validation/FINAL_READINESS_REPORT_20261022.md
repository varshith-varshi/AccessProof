# AccessProof — Enterprise Customer Simulation & Reliability Report
**October 22, 2026 | LOCAL testing only | No production changes**

## Executive result
**Improved local integration confidence, but customer Protect is still NO-GO.**
The current code passed the locally executed customer/Guard/RAG tests and PostgreSQL authorization checks. One critical known provenance weakness remains a strict expected failure.

## Execution evidence
| Validation | Actual result |
|---|---|
| Initial Python baseline | 467 passed, 1 expected failure |
| Final full Python suite | **478 passed, 1 strict XFAIL**, 5 deprecation warnings |
| TypeScript SDK | **12 passed**, including new adversarial cases |
| Three fake customer HTTP journeys | **3 passed** |
| Playwright desktop/mobile | **25 passed, 1 skipped** |
| Isolated PostgreSQL 17 / Redis 7 | Healthy, loopback ports only |
| PostgreSQL Alembic migrations | PASS, latest head `c4d6e8f0a215` |
| PostgreSQL authorization/concurrency matrix | **10/10**, 20 policy events, no deadlocks |
| Modified Python Ruff, compileall, diff whitespace | PASS |
| Repeatable seven-stage local runner | All 7 stages PASS; full suite still contains 1 XFAIL |

Runner stage evidence, without double-counting as unique cases:
- Three customer HTTP journeys: 4 passed.
- Google/Microsoft provider contract and chaos subset: 12 passed.
- Identity, revocation, tenant/source binding: 55 passed.
- SDK metadata and release security: 35 passed.
- Activation/certification gate checks: 4 passed.
- 10,000-document Guard-cache load: 1 passed.
- Full Python suite: 478 passed, 1 XFAIL.

Evidence: `customer_simulation/evidence/executed-20261022/test_results.json` and its per-stage logs.
These subsets overlap with the full Python suite. The existing 150 synthetic catalogue entries were not all independently executed.

## AP-CUSTOMER-001 — Confirmed source-ID laundering (FIXED LOCALLY)
A registered source ID silently overrode a conflicting source ID in retrieved framework metadata. A single record could also carry contradictory file/chunk identifiers, with the adapter choosing whichever alias came first.
- **RED:** 6 Python negative cases and 2 TypeScript negative cases failed.
- **ROOT FIX:** validate consistent declared source/resource/chunk identifiers; any contradiction blocks before the model or Guard is called. Configured source may fill a missing value but never overwrite an explicit contradictory value.
- **GREEN:** Python and TypeScript focused tests and all current suites pass.

## AP-CUSTOMER-002 — Mutable retrieval time-of-check/time-of-use (FIXED LOCALLY)
A shared vector-store document could change its identity/content while waiting on Guard authorization and then be passed to the generator under an older approved identity.
- **RED:** 2 Python and 1 TypeScript mutation/snapshot tests failed.
- **ROOT FIX:** pass independently snapshotted document objects to generation, using the same snapshots for authorization metadata. Fail closed on uncopyable/invalid snapshots.
- **GREEN:** Python and TypeScript mutation regressions pass.
- **Limitation:** snapshots do not independently attest that original bytes came from a trusted provider. Real framework object compatibility and memory/copy overhead need pilot validation.

## Three synthetic customers tested
| Company | Registered adapter | Actual lifecycle provider | Confirmed path |
|---|---|---|---|
| Northstar Technologies | Generic Python | Synthetic Google Drive | API signup/source/Guard/app → verified test identity → Guard HTTP → SDK allow/deny → revoke/deny → stale source → audit |
| BlueHarbor Financial | LangChain Python | Synthetic Google Drive **for this lifecycle**, not Microsoft | Same, with framework-shaped adapter input |
| Meridian Global Systems | LlamaIndex Python | Synthetic Google Drive | Same, with framework-shaped adapter input |

The lifecycle creates accounts, source registrations, Guard machines/enrollment and RAG applications through actual local HTTP. **It then inserts trusted test permission and identity fixtures into a disposable SQLite DB** rather than exercising a real OAuth provider sign-in or external ACL collection. Separate source-provider tests use mocked HTTP/Graph/Drive contracts. The three adapter classes were invoked with framework-shaped documents, not fully deployed third-party framework applications.

## Infrastructure validation
Disposable `customer_simulation/compose.lab.yml` runs PostgreSQL and Redis bound to localhost; migrations were applied to the test DB only. The existing `scripts.validate_postgres_authorization_matrix` completed 10 checks, including concurrent deliveries, out-of-order updates, multi-grant revocation and cross-tenant collisions. This is not an HA/soak certification.

## Remaining release blockers
1. **CRITICAL, UNRESOLVED:** `tests/security/test_known_provenance_integrity_gap.py` remains strict XFAIL. Metadata claiming an authorized source cannot by itself attest actual content bytes. Provider-origin integrity, trusted chunk digests, complete tool/cache/model-input trace and response boundary certification remain necessary.
2. **No full automated customer-route certification:** one-click preflight cannot currently verify every customer-owned API/tool/cache/SSE/WebSocket response path and authenticated Guard acknowledgement.
3. **Real Google Workspace is NOT RUN:** actual OAuth, effective ACL/directory, real identity, Shared Drives, and measured source-to-Guard revocation latency.
4. **Real SharePoint/OneDrive is NOT RUN:** native inheritance, effective site/library/item rights, SharePoint groups, links, guests, owner semantics and authorized test-tenant certification remain incomplete.
5. **Not independently executed:** all 150 historical scenario catalogue combinations, 100k-document soak, full production-like multiworker failover, backup/restore drills, full third-party RAG applications and real network response-byte observation.
6. **No production rollout:** local fixes are not yet deployed and customer data was not used.

## Files changed/added this session
- `packages/rag_sdk/adapters.py`: Python source alias validation and snapshots.
- `packages/rag-sdk-typescript/src/index.ts`: TypeScript parity.
- `tests/security/test_customer_adapter_source_confusion.py`: RED→GREEN cases.
- `packages/rag-sdk-typescript/test/source-identity-confusion.test.mjs`: RED→GREEN cases.
- `tests/integration/test_customer_lifecycle_over_http.py`: 3 synthetic companies, actual adapter and Guard HTTP path.
- `customer_simulation/compose.lab.yml`: isolated ephemeral DB/Redis stack.
- `customer_simulation/run_full_enterprise_validation.py`: reproducible local execution plus per-stage JSON evidence.

## Go/no-go
**PASS:** Supported local synthetic authorization regressions, selected provider error tests, TCP-bound Guard/RAG path, bounded cache performance and PostgreSQL authorization/concurrency.
**NO-GO:** Unrestricted enterprise/customer Protect activation; remain fail-closed until provenance integrity, actual route observation and real provider effective permissions are independently proved.

This audit does not guarantee that no issues will arise in a real customer's environment.
