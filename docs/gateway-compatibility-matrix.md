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
