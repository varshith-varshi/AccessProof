# Gateway compatibility matrix

| Capability | Status | Evidence |
|---|---|---|
| Docker Gateway image | VERIFIED | Local image build and health check |
| Strict attested Gateway route | VERIFIED | Gateway security tests |
| OpenAI-compatible non-streaming model | VERIFIED | Mock endpoint tests |
| Anthropic Claude native Messages API (text-only) | VERIFIED_LOCALLY_PROVIDER_PENDING | Request/response contract and Guard security tests with mocked provider, official endpoint pinning |
| Google Gemini native GenerateContent API (text-only) | VERIFIED_LOCALLY_PROVIDER_PENDING | Request/response contract and Guard security tests with mocked provider, official endpoint pinning |
| Proprietary custom text-only model adapters | EXTENSIBLE_REVIEW_REQUIRED | Explicit installed Python ModelAdapter contract, no universal auto-interception |
| Native external provider Docker egress isolation | VERIFIED_LOCALLY_PROVIDER_PENDING | Static private-RAG/Gateway-only egress tests; actual cloud/model networking and data governance unverified |
| Customer-side Drive text/plain ingestion sidecar | VERIFIED_LOCALLY_PROVIDER_PENDING | Container build, signer/snapshot tamper/expiry and protected reference RAG tests; live Google validation outstanding |
| Generic Python SDK | VERIFIED | Existing regression suite |
| TypeScript SDK | PARTIALLY_VERIFIED | Existing package tests; not rerun in this change |
| LangChain/LlamaIndex/Haystack no-code | UNSUPPORTED | SDK adapters require integration validation |
| Buffered HTTP SSE response | VERIFIED_LOCALLY | Model fully buffers and Guard Layer 2 accepts before the first SSE byte; not live upstream token streaming |
| WebSocket/live model token streams | UNSUPPORTED | Not certified; no response may bypass Layer 2 |
| Google Drive live provider | BLOCKED | Requires authorized Workspace sandbox |
| SharePoint/OneDrive Protect | BLOCKED | Effective permission certification required |

## Provider-neutral Gateway V1 reference extension (2026-10-27)

| Capability | Status | Evidence |
|---|---|---|
| Vendor-neutral signed snapshot entrypoint (`/v1/snapshots/chat/completions`) | VERIFIED_LOCALLY | Independently signed Google Drive/SharePoint source snapshots and real local Guard's source-bound policies exercised; no external tenant credentials used |
| One reusable Gateway implementation across Google Drive and SharePoint | VERIFIED_LOCALLY | Two distinct application/source bindings accepted by the same Gateway code, ALLOW and DENY tests |
| One RAG request combining unrelated source IDs | NOT_SUPPORTED_FAIL_CLOSED | Current Guard binds exactly one source per application; mixed sources are rejected by input validation |
| Reauthorize pre-generated/cache/tool-dependent text (`/v1/responses/authorize`) | VERIFIED_LOCALLY_CONDITIONAL | Signed answer manifest + source attestation + per-request Guard check; requires all customer return paths actually use the endpoint |
| Prevent browser/CDN storage of employee-specific Gateway output | VERIFIED_LOCALLY | no-store, no-cache, Authorization/Cookie Vary response headers; intermediary infrastructure validation pending |
| Arbitrary uninstrumented third-party RAG auto-interception | NOT_SUPPORTED | Source lineage, token identity, mandatory routing and cache/stream bypass proof remain customer-specific |
| Live SharePoint site and Graph document read/write | VERIFIED_PROVIDER_CONNECTOR | Synthetic test folder/files observed in tenant; independent AccessProof Graph app and Entra employee E2E remains pending |
