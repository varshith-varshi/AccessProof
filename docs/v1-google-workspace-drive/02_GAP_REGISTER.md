# V1 gap register

| Gap | Status | Release effect |
|---|---|---|
| Google Drive source/provider scope bypass | Fixed by server-side scope policy and regression test | Closed locally |
| Browser submission of Google OAuth credentials | Fixed; server OAuth callback remains the credential path | Closed locally |
| Effective permissions across customer Shared Drives, nested groups, link sharing and inherited folders | Requires real Workspace validation | External validation gate |
| Revocation propagation latency and stale-policy failure modes | Requires measured tenant run | External validation gate |
| Customer RAG provenance adapter compatibility | Contract exists; each RAG must validate document IDs and identity claims | Per-customer gate |
| OAuth consent screen, scopes and redirect URI | Operator configuration required | Deployment gate |

No entry marked as an external validation gate is claimed as production-proven by local tests.
