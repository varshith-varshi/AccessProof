# Adapter and enforcement inventory

This inventory describes the repository at the current release. A capability is
listed as available only where the code path and automated tests support the
claim.

| Capability | Classification | Evidence / boundary |
| --- | --- | --- |
| Shared Guard Layer 1 resource filtering | IMPLEMENTED_AND_TESTED | `apps/guard/accessproof_guard/app.py` and Guard API tests |
| Shared Guard Layer 2 provenance check | IMPLEMENTED_AND_TESTED | `check-output` consumes a one-time decision context |
| Bounded response release | IMPLEMENTED_AND_TESTED | `packages/rag_sdk.protection.ProtectedRAG` |
| OIDC/JWKS employee identity verification | IMPLEMENTED_AND_TESTED | Guard identity verifier; static HMAC is local-test only |
| Tenant/application binding | IMPLEMENTED_AND_TESTED | Guard policy context and control-plane ownership checks |
| Google Drive permission source | IMPLEMENTED_AND_TESTED | Source connector and provider sync tests |
| Microsoft 365/SharePoint source | PARTIALLY_IMPLEMENTED | Connector exists; deployment/provider permissions still require customer validation |
| Python framework-neutral adapter | IMPLEMENTED_AND_TESTED | `RAGAdapter`, contract tests |
| LangChain Python adapter | IMPLEMENTED_NOT_FRAMEWORK_CERTIFIED | Contract behavior is tested; the repository does not pin and invoke a real LangChain release |
| LlamaIndex Python adapter | IMPLEMENTED_NOT_FRAMEWORK_CERTIFIED | Node mapping behavior is tested; the repository does not pin and invoke a real LlamaIndex release |
| Haystack Python adapter | IMPLEMENTED_NOT_TESTED | Uses the same normalized contract; validate against the customer's Haystack version |
| Generic HTTP target | IMPLEMENTED_AND_TESTED | Private runner connectivity/evidence parser; not Layer 1 enforcement |
| TypeScript framework-neutral SDK | IMPLEMENTED_AND_TESTED | `packages/rag-sdk-typescript`; Layer 1 filtering and Layer 2 buffered release tests |
| LangChain TypeScript structural adapter | IMPLEMENTED_NOT_FRAMEWORK_CERTIFIED | Typed document adapter exists; a real LangChain JS release is not pinned or certified |
| Java/.NET/Go/Rust SDKs | NOT_IMPLEMENTED | Not advertised in the registry |
| LangGraph and agent frameworks | UNSUPPORTED | No trusted retrieval hook implementation in this repository |
| Vector database-specific adapters | UNSUPPORTED | The application must preserve authoritative source IDs in its own retriever |
| Adapter registry | IMPLEMENTED_AND_TESTED | Static metadata endpoint; control plane never executes customer code |
| Browser-based Guard onboarding | IMPLEMENTED_AND_TESTED | Loopback setup exchanges the one-time token without exposing the machine credential |
| Web-v2 integration discovery | IMPLEMENTED_AND_TESTED | `/integrations` reads reviewed compatibility and certification metadata |

The authoritative permission source remains separate from the RAG adapter. A
vector index or LLM citation is not treated as an authorization authority. Any
adapter that cannot filter before generation and hold the response for Layer 2
must remain partial or unsupported.
