# Customer RAG SDK integration (current truthful contract)

Use the **same real application route and guarded document generation/release** for any future self-test; do not configure a separate happy-path demo and claim every customer route protected.

Python (`packages.rag_sdk.ProtectedRAG`): pass the employee's cryptographically verifiable OIDC token, exact configured `application_id`, retrieved `RetrievedResource(source_id, provider_resource_id, chunk_id?, content?)`, and a model callback that consumes only the Layer1-approved list. Supply `source_trace` as a **trusted application-owned callable** returning every actual retrieval/cache/tool/context dependency. The SDK now refuses missing provenance in Protect and never lets model output out before Layer2. New regeneration must produce a fresh trace. The sample `drive-rag-demo` records its actual generator's allowed inputs.

TypeScript (`packages/rag-sdk-typescript`): explicit trusted `sourceTrace` required, strict mode/delay checks, chunk-scoped matching, late-source reauthorization, fail-closed callback handling, bounded UTF-8 response size. Typescript build and 7 Node tests passed. Framework adapter source IDs must be immutable actual provider file/item IDs, not guessed text/document titles or browser metadata.

**Missing integration:** SDK route/build signed manifest, real test-route driver, token-by-token SSE/WebSocket boundary observer and machine-authenticated automated challenge interface. A `sourceTrace` callback on its own is not proof of comprehensive tool/route interception. Install Guard next to the RAG's backend service (not on each employee laptop) and prevent direct unwrapped access paths.
