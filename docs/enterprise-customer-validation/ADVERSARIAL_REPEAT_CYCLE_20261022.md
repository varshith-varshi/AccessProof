# AccessProof — Adversarial Multi-Cycle Audit (October 22, 2026)

**Scope:** Authorized local repository `/home/white-devil/Downloads/accessproof/f15`. Synthetic customer, Guard and SDK environments only. Production hosts, production databases and live provider permissions were **not** modified or attacked. Existing uncommitted changes were preserved.

## Verdict

**Local regression pass with critical outstanding enterprise certification blockers.** The new red-team attacks below found real bugs, reproduced them with deterministic RED tests, and corrected the concrete defects. An existing architecture-level expected failure involving legacy metadata-only provenance remains open. No claim of complete customer Protect readiness is justified.

## Confirmed defects and remediation

| ID | Finding and attack oracle | Result |
|---|---|---|
| AP-RED-101 | **High:** TypeScript framework document held a shallowly copied nested `node`; when the vector store changed `node.text` after Guard Layer 1, the generator emitted restricted synthetic content although precheck saw an authorized item. RED→GREEN using deep isolated document state. | FIXED LOCALLY |
| AP-RED-102 | **High:** TypeScript `pageContent` could claim safe text while framework `getContent()` returned entirely different protected content. RED→GREEN: the adapter now compares effective and canonical document content before invoking Guard/model. | FIXED LOCALLY |
| AP-RED-103 | **High (test-tool boundary):** Route-probe configuration validated a safe local URL but accepted a caller-provided HTTP client pointing elsewhere, risking test identity tokens sent to an unintended server. RED→GREEN: verify actual client origin equals the configured local origin. | FIXED LOCALLY |
| AP-RED-104 | **High (test-tool boundary):** A caller-provided HTTP client with redirect-following enabled could follow an unexpected RAG redirect, defeating route restrictions. RED→GREEN: force `follow_redirects=False` for every challenge. | FIXED LOCALLY |
| AP-RED-105 | **High (verification accuracy):** Raw-byte canary scanning missed JSON/SSE Unicode-escaped protected content which customer browsers decode and show. Two RED attack tests; changed probe to parse full decoded payloads and check strings across event chunks. | FIXED LOCALLY |
| AP-RED-106 | **Medium (verification accuracy):** Even an invalid-identity HTTP 401 body could leak escaped protected content without triggering the observer. RED→GREEN: decode JSON error bodies and examine their strings. | FIXED LOCALLY |
| AP-RED-107 | **High (exception handling):** If an opt-in TypeScript content verifier threw, the SDK rejected its Promise rather than returning an explicit deny, potentially reaching a permissive customer fallback. RED→GREEN: catch failures at Layer 1 and Layer 2 verification boundaries. | FIXED LOCALLY |
| AP-RED-108 | **Medium (compatibility):** The deep-snapshot fix dropped nested LlamaIndex class `getContent()` behavior and blocked an otherwise authorized request. RED→GREEN: restore a stable isolated nested content accessor while continuing to reject mismatches. | FIXED LOCALLY |
| AP-RED-109 | **High (previous capability gap):** TypeScript lacked parity with Python's signed-provider-byte verification. Added opt-in Ed25519 verification over tenant, app, source, resource, chunk, revision, expiry and SHA-256 content, plus strict trace validation. A test confirms an actual Python-signed fixture verifies correctly in TypeScript. | IMPLEMENTED LOCALLY; NOT CERTIFIED |

**Security boundaries maintained:** Signed content checks are opt-in and require a *trusted separate ingestion service* to hold private keys. Invalid signatures, wrong identities/versions, stale signatures and untrusted late tool content cannot become positive model inputs in the tested SDK paths. No customer activation flags were weakened.

## Test execution

- **Final full Python suite:** **526 passed, 1 strict expected failure**, 5 dependency deprecation warnings.
- **Final TypeScript SDK suite:** **33 passed** with TS compile/build.
- **Playwright browser suite:** **25 passed, 1 skipped** (desktop/mobile).
- **Actual repeated focused adversarial loops:** **5 cycles × 46 checks = 230 passing test executions**; these were intentionally repeated cases, not 230 distinct scenarios.
- **Additional route-observer focused suite:** **22 passed**.
- **Ruff / compileall / `git diff --check`:** passed for modified Python code.
- **Provider/Guard/customer HTTP contract tests:** covered in the complete Python suite.
- **Real Google Workspace/SharePoint/OneDrive:** **NOT RUN**.

Relevant reproducible evidence files on the laptop:

`/tmp/accessproof_nested_ts_red_20261022.log`; `/tmp/accessproof_nested_ts_green_20261022.log`; `/tmp/accessproof_route_probe_red_20261022.log`; `/tmp/accessproof_encoded_route_red_20261022.log`; `/tmp/accessproof_invalid_error_red_20261022.log`; `/tmp/accessproof_ts_verifier_error_red_20261022.log`; `/tmp/accessproof_llama_nested_red_20261022.log`; `/tmp/accessproof_llama_nested_green_20261022.log`; `/tmp/accessproof_ts_python_interop_20261022.log`; `/tmp/accessproof_deep_redteam_final_full_20261022.log`; `/tmp/accessproof_cycle_1.log` through `/tmp/accessproof_cycle_5.log`.

## Core remaining architectural risks

1. **CRITICAL — legacy metadata-only provenance.** `tests/security/test_known_provenance_integrity_gap.py` still has a strict XFAIL: forged resource metadata may label restricted model input as an authorized source. Optional signed-content SDK verification does NOT cure untrusted provider ingestion or complete prompt/tool/cache trace capture by itself. Existing customer Protect cannot be certified.
2. **HIGH — incomplete customer-side automatic route coverage certification.** Need an authenticated, nonce-bound real customer route challenge worker, independent response-byte observer, full route inventory and validated Guard Protect acknowledgement. Local route-probe passes do NOT establish that all RAG/WebSocket/tool endpoints were checked. Control-plane activation gates remain closed.
3. **HIGH — real Microsoft effective permissions.** SharePoint site/library/item inheritance, native groups, sharing links, external guests, OneDrive ownership, remote items and revocation need an owner-authorized real tenant and independent authorization oracle.
4. **HIGH — real Google Workspace permissions and identity.** Test Workspace OAuth scopes, Directory and shared-drive ACLs, verified employee OIDC, actual provider-confirmed revocation latency, token rotation, provider partial/failure semantics.
5. **MEDIUM/HIGH — TypeScript framework coverage remains narrower than arbitrary customer pipelines.** Deep snapshot and effective content checks protect tested framework shapes; independent customer tool/memory prompt paths and unconventional custom getters require integration-specific certification.
6. **MEDIUM — diagnostic canary checks are not proof of absence of all leakage.** The observer now parses JSON/SSE decoded strings but cannot detect every semantic rephrasing, novel encoding, alternate route or non-canary confidential material. Do not promote its local result to a Protect activation certificate.
7. **Operational:** production-like multiworker failover, real provider rate limits, long-duration soak, customer SDK version negotiation, browser/customer route deployment and end-to-end production release boundary still require authorized validation.

## Changed files from this cycle

- `packages/rag-sdk-typescript/src/index.ts`: nested-node deep snapshot, getContent consistency and accessibility; signed-content boundary integration; strict output trace; exception-safe failure.
- `packages/rag-sdk-typescript/src/attestation.ts` **new**: isolated public-key Ed25519 verification.
- `packages/rag-sdk-typescript/test/nested-content-integrity.test.mjs` **new**: RED→GREEN nested mutation, mismatched effective text and LlamaIndex compatibility.
- `packages/rag-sdk-typescript/test/source-attestation.test.mjs` **new**: signed byte/model input, negative provenance and cross-language test cases.
- `packages/rag-sdk-typescript/test/python-source-attestation-fixture.json` **new**: synthetic Python-signed fixture with fixed test clock; no signing private key.
- `customer_simulation/route_probe.py`: local transport origin/redirect hardening and decoded JSON/SSE body inspection.
- `tests/unit/test_local_customer_route_probe.py`: RED→GREEN network-boundary and encoded-output adversarial tests.

## Final decision

**Improved and locally tested; NOT READY for unrestricted customer Protect.** Do not deploy or enable Protect until real provider provenance, authenticated route certification and source-effective permissions have been demonstrated. This iteration did **not** modify the live EC2 stack or real customer systems.
