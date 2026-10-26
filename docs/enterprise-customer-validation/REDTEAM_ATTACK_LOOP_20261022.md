# AccessProof — Deep Local Red-Team Attack Loop, 22 October 2026

**Scope:** Local owner-authorized repository, fake providers, Guard, SDK and synthetic customer HTTP. Production untouched; no customer secrets or real provider mutations.
**Verdict:** LOCAL REGRESSION PASS; CUSTOMER PROTECT NO-GO.

## Reproduced and mitigated defects

| Finding | Before fix | Mitigation implemented |
|---|---|---|
| TS Guard Layer2 null and missing-reason allow | 2 negative tests failed | Validate Layer1 and Layer2 response shape; return controlled block |
| TS late-source composite key delimiter collision | 1 negative test failed (one Layer1 instead of two) | Compare encoded identity tuples instead of joined strings |
| Contradictory duplicate grants, Python and TS | 3 Python and 3 TS negatives failed | Reject conflicting resource/chunk scopes before generation |
| Python framework deepcopy returns same mutable object | 1 negative test failed; changed content reached model | Reject shared object/metadata/node snapshots before Guard call |
| Python strict regeneration missing signed source inputs | 1 negative test failed; response was released | Require complete attested trace for every regenerated input |
| Drive persisted record adopts unrelated provider item | 1 negative test failed | Provider GET verifies exact name, description, parent and marker-derived file name |
| Microsoft persisted record adopts unrelated item | 1 negative test failed | Provider GET verifies drive, parent, exact name, marker-derived file name |
| Microsoft malicious resource ID reaches Graph URL | 4 negative tests failed | Reject unsafe URL delimiters and invalid provider IDs before provider I/O |

All listed negative regressions passed after their corresponding fixes. Identical duplicate grant positive controls and valid synthetic resource recovery also passed.

## Additional real Guard scenario

A policy revoke introduced during the generator callback (after Layer1 but before Layer2) caused the Guard to return LAYER2_ACCESS_REVOKED. The SDK returned no answer. **PASS** in local HTTP simulation; real provider timing not measured.

## Verified execution

- Python entire suite: **521 passed, 1 strict XFAIL**; 5 library deprecation warnings.
- TypeScript SDK suite: **23 passed, 0 failed**.
- Browser Playwright: **25 passed, 1 skipped**.
- Eight-stage enterprise customer runner: all PASS. Subsets overlap full suite.
- Synthetic provider/connector suite: **20 passed**.
- Synthetic source attestation/SSE subset: **31 passed**.
- Identity/revoke isolation subset: **55 passed**.
- Customer HTTP subset: **5 passed**.
- SDK security subset: **40 passed**.
- Activation safety subset: **4 passed**.
- 10k-resource cache subset: **1 passed**.
- Ruff and diff whitespace: PASS.
- Evidence: `customer_simulation/evidence/executed-20261022/test_results.json`.

## Remain open — serious customer-production blockers

**CRITICAL: Legacy metadata-only source provenance still unsafe** (`tests/security/test_known_provenance_integrity_gap.py`, strict XFAIL). Source-attested content proof is only opt-in and synthetic; real provider ingestion, full generator/tool/cache manifest and TypeScript SDK parity incomplete.

**CRITICAL: Automated complete-route challenge/certification missing.** `CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED` is intentionally active. Local probe does NOT certify all customer endpoints or authorize Protect activation.

**HIGH: Real Google Workspace, SharePoint and OneDrive authorization not validated.** Native effective permissions, group/inheritance/guest/link semantics and real revoke-to-deny timing still need owner-authorized test tenants. Microsoft source certification remains gated.

**HIGH: Arbitrary framework data objects and unwrapped output routes require further isolation validation.** Deepcopy rejection covers identified aliases but not arbitrary mutable/proxy objects.

**MEDIUM/HIGH: Synthetic test-resource adoption is better checked, but provider state could move or change between adoption and later mutation.** Stronger per-operation recheck/conditional provider writes and durable original ownership receipts remain advisable. New marker-derived naming may require controlled manual cleanup for historical synthetic test files.

**No production deployment or customer credential access occurred.** Do not relax gates or claim no future issues.
