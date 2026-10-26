# Gateway-only V1: public SDK retirement and release boundary

**Date:** 26 October 2026  
**Source tree:** /home/white-devil/Downloads/accessproof/f15  
**Target:** Google Workspace + Google Drive customer-side Gateway integration

## Shipping architecture

1. Google Workspace administrator authorizes an approved Google Drive root through
   server-owned OAuth. Durable directory/ACL jobs produce revisioned source policy.
2. The enrolled customer Guard installs source policy, identity bindings, revision,
   and acknowledgement work as an atomic transaction.
3. The customer RAG uses the reviewed HTTP Gateway boundary. Retrieved resources
   require independently verified Ed25519 content attestations; verified employee
   identity and source IDs are checked by the Guard before generation.
4. Gateway buffers generation and verifies source dependency/provenance under
   the applicable authorization revision before returning employee content.
5. The supported route must pass nonce-bound allow, deny, forgery and cutover
   checks. Missing policy/source/route evidence keeps Protect blocked.

## Public integration changes

- The public Python RAG SDK distribution path packages/rag_sdk was removed.
- The public TypeScript RAG SDK packages/rag-sdk-typescript was removed.
- Framework wrapper classes RAGAdapter, LangChainAdapter, LlamaIndexAdapter and
  HaystackAdapter were retired instead of being silently kept as an alternative
  customer integration channel.
- The authorization, attestation, ingestion, authorization-first retrieval and
  cache security primitives were moved to **packages/rag_core**. This is a
  private in-repository implementation dependency used by Gateway, not a
  customer installation method. Gateway continues to use these protected
  algorithms; no security logic was replaced with bypasses.
- The production integration registry exposes exactly one customer integration:
  accessproof-gateway; the API rejects new generic-python, generic-typescript,
  generic-http and framework registrations at the Pydantic boundary.
- Previously stored legacy integration records are retained for audit/history.
  The Protect readiness check refuses non-Gateway records; no automatic
  migration promotes historical SDK integrations to PROTECTED_VERIFIED.
- web-v2 /integrations is a Gateway installation/review screen, no framework
  catalog, SDK code snippets or SDK download flow. /applications has a fixed
  Gateway integration field and no adapter selector. The sidebar calls it
  Gateway setup.
- The Guard release packaging script ships the internal OIDC/HTTP dependencies,
  not the removed SDK. The standalone TypeScript SDK CI job was removed.
- Historic SDK-focused tests were archived outside the active checkout.
  Applicable Guard/Gateway policy, source attestation and cache security
  regression tests remain, and new Gateway-only API/UI regressions were added.

## Physical archives retained, not used in product

- /home/white-devil/Downloads/accessproof/retired-public-rag-sdk-typescript-20261026
- /home/white-devil/Downloads/accessproof/retired-rag-framework-wrappers-20261026

These archives are outside the repository and MUST NOT be deployed, published,
used as package dependencies, or reintroduced into customer onboarding.

## Scope and safety

A transparent reverse proxy **cannot independently know** which documents an
unmodified retriever supplied to its model, or whether a cache/tool path
bypassed the proxy. Therefore Gateway is NOT universal zero-code RAG protection.

Supported V1: the reviewed, customer-owned Docker route with authenticated
employee, complete intercepted model call, attested retrieval resources,
buffered model output, source ACL policy and Guard route certification.

Explicitly unsupported as production-certified: direct model egress outside
Gateway, opaque/unattested source metadata, native incremental streaming,
WebSocket, tools/agents, arbitrary cache return paths and untested providers.

## Verification and release gate

Tests must prove Python imports without packages.rag_sdk, customer Guard archive
build/import/checksum without SDK, Gateway integration registry exactly one
entry, direct API registration rejection for retired adapter types, browser
workflow without SDK controls, atomic Guard authorization and signed content
tampering tests. Frontend typecheck/lint/build and complete Playwright tests
are required before a tagged release.

**Production release is not authorized by this refactor.** Real Workspace
identity/Drive permission checks, real provider revocations, live customer RAG
route tests, backup/restore, incident drills, staging rollout and independent
security review remain outstanding. No production server is modified by this
work, and no Google OAuth customer credentials were used.

