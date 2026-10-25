# Four adversarial findings — before/after

At baseline, all 4 dedicated tests failed. They were rerun after implementation and passed. Logs: `/tmp/accessproof_v2_four_red_20261022.log` and `/tmp/accessproof_v2_four_green_20261022.log`.

| Finding | Baseline reproduction | Root fix | After |
|---|---|---|---|
| ACL reconciliation starvation | 4 resources; limit=2; 3 rounds only `file-0,file-1` | Independent durable `last_reconciled_at` order, per-resource advancement; new reversible Alembic | PASS: all 4 eventually examined |
| Reassigned permission ID | `permission-1` switched old group→new user; old grant never revoked | Fingerprint grant key bound to source resource, principal, role/expiry/access path, so old key is separately revocable | PASS: old subject revoke and new verified subject upsert queued |
| Missing complete RAG provenance | `source_trace=None` let protected answer containing fake untraced cache material be returned | Python and TS deny absent trusted trace, enforce allowed metadata, late-source/check-output boundaries | PASS: model not called for uncaptured trace |
| Microsoft v2 admin consent scope | `authorization_url` omitted `scope` | Explicit tenant-specific `https://graph.microsoft.com/.default`; state and callback binding preserved | PASS: expected v2 query scope included |

Further discovered TS-only regressions (also RED→GREEN): Protect did not reject observational `would_allow` and failed to filter an unapproved chunk with the same resource ID. Exact suite: `packages/rag-sdk-typescript/test/protect-mode-boundary.test.mjs`, both pass. This is a local SDK test, not independent verification of a real customer RAG's every route.

Known limitations: the fingerprint key strategy and fair reconciliation need positive/negative concurrency and 10k/100k provider-scale tests, and native SharePoint ACL inheritance requires a different effective policy oracle. Passing these 4 does not certify Microsoft Protect.
