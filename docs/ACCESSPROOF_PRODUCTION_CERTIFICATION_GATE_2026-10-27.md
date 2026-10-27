# AccessProof production certification gate — October 27, 2026

**Verdict: NOT PRODUCTION CERTIFIED.** No certification evidence for universal customer RAG security can be honestly issued from the current environment.

## Evidence collected

| Gate | Evidence | Status |
| --- | --- | --- |
| Live Microsoft SharePoint document inventory | Connected delegated Microsoft Graph account fetched all three existing synthetic SharePoint files and read their grant lists. Shared: Alice/Bob direct read; Finance: Alice direct read; Engineering: Bob direct read. | LIVE PROVIDER INVENTORY VERIFIED |
| Genuine Entra Alice and Bob sign-in | AccessProof Entra web app client credentials and callback configuration absent. This connector session is not either synthetic employee login. | BLOCKED |
| Employee-effective denial | Missing direct grant is not effective 403. The connected SharePoint app is an admin/current delegated identity, not Alice/Bob. | BLOCKED |
| Live SharePoint permission revoke | No source permission was removed, no employee delegated 403, no stable denial measurement. | BLOCKED |
| Google Workspace employee test | Available Drive connector uses personal account document shares; verified Workspace-managed employee identity and OAuth not configured. | BLOCKED |
| Signed source content and real local model | Actual synthetic Finance text mirrored from connected SharePoint into an ignored, locally permission-restricted test fixture. Signed for test ingestion; Guard V2, Gateway and actual Ollama llama3.2:3b performed authorized Alice test, Bob-denial test and local ACL-revoke-denial test. | LOCAL INTEGRATION PASSED, NOT LIVE EMPLOYEE TEST |
| Synthetic multi-source Gateway with real local model | Independent synthetic signed Google and SharePoint sources, actual Guard, actual Ollama: 3 tests passed for authorized, source-denied and in-flight local revocation response. | LOCAL INTEGRATION PASSED |
| Signed cache and SSE denial | Gateway route/Guard tests prove simulated revoke and denied source block cache hits and streaming responses. Actual customer cache route not proven. | LOCAL TEST PASSED; CUSTOMER BLOCKED |
| Unprotected alternate RAG route | Independent running SharePoint-RAG lab had reachable /chat with no employee bearer, and no indexed files. Local LAB_ENABLE_BASELINE changed to 0 and RAG service recreated; rerun verifies /chat responds 503 UNPROTECTED_BASELINE_DISABLED; /chat/protected without token responds 401. No secrets or source grants changed. | LOCAL BYPASS REMOVED |
| Network-exclusive Gateway route | Hardened static verifier updated to reject published RAG ports (including 127.0.0.1); hardened example no longer publishes its RAG port. Actual developer deployment remains unsuitable for certification. | CODE FIXED; LIVE CUTOVER BLOCKED |
| Production load, backup/restore, deployment and independent penetration | Not completed. | BLOCKED |

## Exact blockers needing operator-controlled inputs

1. Configure a separate single-tenant Microsoft Entra web-app registration (client ID/secret, approved callback URI, openid/profile/email scopes) for real Alice and Bob interactive sign-in, with tenant-scoped verifier and immutable oid/tid mapping.
2. Configure a separate, least-privileged Microsoft Graph ingestion app with selected site access to the existing synthetic test folder; this app must not be the browser-login OAuth client.
3. Complete employee-delegated GET and 403 tests for each test file, including shared positive controls; then revoke a synthetic test grant and capture source denial timestamps and RAG/cache response denial (no real customer data).
4. Supply managed Google Workspace/Cloud Identity identities and a narrowly scoped Drive test folder, with trusted OIDC, group/share-link revocation cases, and provider-effective checks.
5. Configure customer RAG image, isolated real model endpoint, consented signed ingestion, storage/caches, verified output coverage and sanctioned network access; run actual bypass and load probes and keep negative results as failures.

## Guardrails

- Neither local test JWTs nor the SharePoint connector's administrative delegation are substitutes for Alice/Bob real employee login.
- Signatures generated over a locally mirrored SharePoint document authenticate **the local test ingestion**, not a Microsoft-origin cryptographic source signature.
- Local source ACL change is NOT live provider revocation. Revocation lag remains unknown.
- The independent SharePoint RAG lab has zero indexed documents; hardened baseline status alone is not proof of protected data retrieval.
- No unapproved provider mutation, paid license purchase, production cutover or customer traffic modification occurred.
- The optional local provider fixture is stored outside Git and must not be committed.

## Reproducible validation paths

Run targeted integration tests from the repository with the ROS pytest autoload disabled:
- tests/integration/test_gateway_real_local_ollama.py (3 local model tests)
- tests/integration/test_live_sharepoint_fixture_ollama.py (opt-in private source fixture test)
- tests/unit/test_gateway_network_boundary.py (now rejects RAG direct published port)
- tests/security/test_gateway_all_response_routes.py
- tests/security/test_multisource_cached_answer_v2.py

Until all live-employee, real-provider, cache, alternate egress and customer authorization gates are independently tested, the product's status is **NOT CERTIFIED FOR PRODUCTION**.
