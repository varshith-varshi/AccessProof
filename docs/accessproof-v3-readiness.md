# AccessProof V3 local readiness record

Status: **local SDK and control-plane hardening only; not a production release certification**.

## Evidence completed locally

- V3 Protect mode accepts a legacy `regenerate` callback for compatibility but
  never invokes it after Layer 2 rejects an answer.
- Signed cached-answer manifests bind tenant, application, answer digest,
  producer identity, complete dependency provenance, and expiry.
- Cache delivery rechecks current employee authorization through both Guard
  layers; historical cache authorization is never reused.
- Fresh SQLite migration to `e6f8a2c4d9b0` completes successfully.
- Focused Python security/regression tests and the TypeScript SDK suite pass.

## Not yet established by local tests

- A customer's real Google Workspace/SharePoint effective permissions,
  group nesting, shared-drive semantics, and revocation timing.
- An independently deployed customer RAG/cache integration using the V3 cache
  contract.
- Load, availability, failover, and latency targets under customer production
  traffic.
- Provider-specific cache invalidation. Authorization still blocks unsafe
  cache hits when direct invalidation is unavailable.

Do not represent this record as a claim that arbitrary caches, arbitrary RAG
frameworks, or opaque model-provider caches are automatically protected.
