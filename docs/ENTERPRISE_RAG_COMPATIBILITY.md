# Enterprise RAG compatibility — evidence-based scope (2026-10-27)

| Component | Reference supported path | Certification limitation |
| --- | --- | --- |
| SharePoint / Microsoft 365 | Trusted source snapshots, distinct source ID, Graph connector code present | Fresh real Entra+Graph permission validation pending |
| Google Drive / Workspace | Existing verified source snapshot flow and connector code | Real cross-provider mixed application not exercised |
| LangChain, LlamaIndex, Haystack, custom | Could call compatible Gateway endpoints | No universal automatic insertion or provenance generation |
| OpenAI-compatible / supported adapters | Existing provider-neutral Gateway model transport | Feature-by-feature tool, structured output, multimodal compatibility not proven |
| Redis / Postgres / Memcached / semantic cache | Existing signed cache authorization infrastructure | Customer cache-hit interception and mixed-source revoke proof pending |
| SSE streaming | Buffered release for supported Gateway route | Incremental token streaming/WebSockets not certified |
| Azure AI Search, pgvector, Pinecone, Qdrant | Compatible only when trusted retrieval contract supplied | Do not claim zero-code or automatic discovery as certification |
| Reverse proxies, egress enforcement | Scoped customer Gateway route | Alternate egress/response paths require customer cutover/network tests |

Classify each requested customer capability as PASS, FAIL, BLOCKED, NOT_TESTED or NOT_APPLICABLE, with the actual evidence reference. Detection of an installed package or connected endpoint is never proof that its employee-facing response is protected.
