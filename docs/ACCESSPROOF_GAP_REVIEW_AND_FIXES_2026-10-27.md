# AccessProof: Remaining Limitations and Verified Fixes
Date: 2026-10-27
Readiness: LOCAL_REFERENCE_VALIDATED for the narrowly defined signed-source Gateway V2 path. NOT production-certified for arbitrary RAG architectures.

## Fixed in follow-up patch
- Added source-qualified, bounded Guard V2 authorization-scope API for pre-retrieval ANN allowsets. Per-source employee mappings and application revisions are required.
- Rejects unsupported V2 resource scopes instead of silently treating them as read.
- Rejects ambiguous duplicate source/resource/chunk data when versions conflict.
- Added real Guard V2 HTTP tests for signed multi-source cached answers: Alice allow, Bob denied SharePoint, revoked ACL denied, changed application revision denied.
- GuardClient validates V2 authorization-scope source sets and requires a complete, bounded per-source resource list.
- Full initial source snapshot repository suite completed with exit status 0 (1,098 passing test indicators).
- Synthetic tests and successful unit suites DO NOT certify real provider integration.

## Remaining blockers
1. Real Microsoft Entra ID + Graph / SharePoint and Google Workspace mixed-source employee requests and permission revokes were not independently executed.
2. Source-side permission changes may not be observed until connector sync. AccessProof checks latest installed policy; it cannot promise zero-lag revocation.
3. Direct model egress, unprotected caches, alternate API responses, tool outputs and unsupervised streaming can bypass supported Gateway routes unless customer cutover/network policies close those paths.
4. Multi-turn prior conversation dependencies have no approved signed lineage ledger; mixed-source routes reject untracked conversation history.
5. Arbitrary RAG retrieval pipelines cannot automatically manufacture trustworthy provider-signed provenance from user-provided prompts.
6. Redis, PostgreSQL, Memcached and semantic-cache customer interception are not comprehensively certified; local signed-cache enforcement now has source-scoped tests.
7. Tool calls, multimodal payloads, arbitrary providers, WebSockets and incremental streaming require dedicated fail-closed implementation.
8. Customer-specific installation/cutover, route probes and independent evidence for multi-source activation are incomplete; Protect activation remains blocked.
9. Production-like performance, provider throttling, backup/recovery and audit delivery testing are still required.
10. GitHub publication uses a source-only private branch: local history has a 873 MB archive, histories diverge, and OAuth lacks workflow-update scope. GitHub main was not changed.

## Reproduction
Run Python tests with the ROS pytest plugin disabled and pytest-asyncio explicitly enabled.
Full base suite: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -p pytest_asyncio.plugin -q tests
Focused additions: tests/security/test_multisource_guard_v2.py, tests/security/test_multisource_cached_answer_v2.py, tests/unit/test_guard_client_multisource_scope.py.

Do not claim production-ready status without provider-specific validation, independent customer-route checks, explicit approval and proof against every protected output path.
