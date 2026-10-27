# AccessProof Gateway architecture — implemented scope (2026-10-27)

```text
Employee verified JWT
         |
  Customer authenticated RAG route
         |
  AccessProof Gateway (bounded HTTP, source-attestation verification)
         |
  Guard V2 /filter-resources (source-scoped identity + current ACL)
         |
  Signed authorized source chunks only
         |
  Configured LLM adapter (provider-specific contract)
         |
  Buffered generated answer
         |
  Guard V2 /check-output (one-time source/version/revision validation)
         |
  Authorized response, or fail closed
```

The Gateway is the protected data plane; the API, database and web-v2 are the control plane. Local Guard policy cache is durable SQLite. Control-plane tenant and source bindings are in PostgreSQL via SQLAlchemy/Alembic, with PostgreSQL RLS on the new association table.

For mixed requests the Gateway uses V2. For single-source legacy routes the existing V1 Guard behavior is preserved. One application-level revision hashes the ordered set of all bound source states and the effective Guard policy version. Protect readiness requires current health of all configured sources. Signed source attestations are verified before model invocation; model output is fully buffered pending Layer 2 release authorization. Gateway can use a separate signed cached-answer route with source dependencies.

This is **not** a universal interception proxy. A customer must prove that the **actual employee-facing request and all response paths**, including tool returns, caches, alternate LLM egress, fallbacks and streaming, go through supported protected routes. Unsupported sources and unsupervised direct model requests remain outside the protection boundary. Automatic topology discovery and universal cache interception are not certified.
