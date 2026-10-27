# Unresolved security and readiness risks

1. **Real Google Drive ACL semantics unproven here (release blocker for real customer data):** Google Groups membership propagation, inherited ACLs, shared drives, moves, shortcuts, domain/link shares, pagination and provider 403/429/500 behavior need an explicitly authorized disposable Workspace with synthetic files.
2. **Customer RAG integration completeness unproven:** independent SDK sample and customer callbacks, history/memory, agent tools, reranking, embedding/index stages, streaming/WebSocket/SSE, alternative endpoints and batch execution require application-specific contract verification. A protected route cannot secure an undocumented unprotected route.
3. **Layer 2 semantic limits:** trusted source traces/citation checks cannot certify every paraphrase/derived secret generated from uncaptured memory or prompt. Do not claim guaranteed prevention of all model hallucinations or latent semantic disclosures.
4. **Source revocation exposure:** real source change → synchronization → enforced denial time not measured against Google Workspace. Synthetic atomic-release tests are not proof of instant revocation.
5. **Deployment and resilience:** no verified production rollback, high-concurrency performance/soak p99, independent IdP/JWKS sandbox, rotating machine credentials, or proven multi-node failover in this run.
6. **Other catalog cases:** A01–K05 not each covered by an explicit independent adversarial negative+positive test; see coverage matrix. Unexecuted cases must not be counted passed.
7. **Integration failure mapping:** customer HTTP handlers must convert `ProtectedResponse(block)` into a genuine non-release and suitable operational error where Guard is unavailable; mock SDK proof alone cannot enforce the caller's choice.
8. **Concurrent edits:** separate local processes were actively executing pytest and modifying source during this audit. Final diff ownership and post-freeze verification are required.
9. **Chunk policy source support:** the SDK now preserves a chunk-scoped allowlist if a Guard supplies one. Current Google Drive V1 policy decisions are file/resource scoped, so real chunk-level source semantics remain unvalidated and must not be advertised without source-provider evidence.

## Unresolved after 2026-10-20 audit continuation

The new audit-backlog protection deliberately fails closed under a long control-plane outage once all pending evidence slots are full. This is the safe confidentiality/evidence-integrity choice but can interrupt customer RAG availability. Production rollout needs monitored queue occupancy, upload retry/backoff, operator alerts, capacity planning and an agreed outage behavior/SLO. No long soak or stress test was run.

Google Workspace effective ACL and group/shortcut/inheritance semantics; OIDC/JWKS against an external issuer; independent customer RAG cache/tool/memory and SSE output paths; real revocation propagation; supported model/framework adapters; throughput/latency/HA recovery; independent penetration testing and 24/7 availability remain unverified. No provider/customer systems were touched.

Other current repository edits were observed during this session. Before a customer pilot, freeze a versioned release and rerun tests, installation, type checking and source-to-image consistency against exactly that release.

## Follow-up residual risks
- The SDK now checks each reported late chunk, but cannot force a customer's uninstrumented RAG routes, tool calls, agent memory, model output, or citation trace to report honest provenance. Whole-application protection is not established.
- Google Drive V1 authorizes at file/resource scope; chunk-scoped Guard responses in these regressions are synthetic future-contract scenarios.
- Migration: existing Guard enrollment or ACL mappings based on custom or mutable OIDC subject claims must migrate to stable sub or oid identifiers, with fresh binding review.
- Sequential MFA recovery-code replay is fixed. The two-transaction concurrent recovery-code claim race remains untested and may require atomic database compare-and-swap before a real high-threat deployment.
- Real Google Workspace groups/inheritance/moves, external IdP/JWKS, live LLM/tool/streaming paths, multi-node failures, and load/soak tests remain unverified.
