# AccessProof RAG adapter contract

AccessProof protects an existing RAG pipeline at two application-controlled
boundaries. The retriever remains the customer's retriever and the model
remains the customer's model:

```text
employee token (verified by Guard)
        -> customer retriever
        -> stable source/resource metadata
        -> Guard Layer 1 filter
        -> customer generator (authorized documents only)
        -> bounded response buffer
        -> Guard Layer 2 provenance check
        -> release or block
```

The shipped Python SDK contract is `accessproof.rag/v1`. It is intentionally
small enough to use from any Python application and does not require a
framework dependency. The reference adapters currently cover:

| Adapter | Input shape | Status |
| --- | --- | --- |
| `RAGAdapter` | mappings or application objects | implemented and unit tested |
| `LangChainAdapter` | LangChain-style `Document` (`page_content`, `metadata`) | implemented and unit tested |
| `LlamaIndexAdapter` | nodes with `get_content()` and `metadata` | implemented and unit tested |
| `HaystackAdapter` | Haystack-style mappings/objects | implemented; uses the generic tests |
| Generic HTTP target | customer HTTP AI target, private runner or HTTPS cloud target | existing runner integration |

This is an adapter contract, not a claim that every framework is supported.
Frameworks with no trusted retrieval hook, no stable resource identifiers, or
no way to hold the response before release require a customer-specific
adapter. AccessProof should report that limitation instead of treating prompt
text, LLM citations, or content hashes as authorization evidence.

## Stable metadata requirements

Every retrieved item must carry:

* `source_id` (or the adapter's configured `source_id`), identifying the
  connected permission source;
* `resource_id` (or `accessproof_resource_id`, `source_resource_id`,
  `document_id`, or `file_id`), identifying the authoritative source resource;
* optional `chunk_id`/`node_id` for chunk-level provenance.

The adapter never derives a resource id from content, vector position, prompt,
or model-generated citations. Missing stable metadata is a configuration error
and fails before generation.

## LangChain example

```python
from packages.rag_sdk import GuardClient, LangChainAdapter, ProtectedRAG

guard = GuardClient("https://guard.customer.example")
adapter = LangChainAdapter(ProtectedRAG(guard), source_id="sharepoint-prod")

result = adapter.run(
    employee_token=request.state.employee_access_token,
    application_id="finance-assistant-prod",
    documents=retriever.invoke(question),
    generate=lambda allowed: llm.invoke(format_context(allowed)),
)
if result.response is None:
    raise PermissionError(result.reason)
return result.response
```

The token is supplied by the customer's authenticated request context. It is
not selected from document metadata and is not stored in browser storage.

## LlamaIndex example

```python
from packages.rag_sdk import GuardClient, LlamaIndexAdapter, ProtectedRAG

adapter = LlamaIndexAdapter(
    ProtectedRAG(GuardClient("https://guard.customer.example")),
    source_id="google-drive-prod",
)
result = adapter.run(
    employee_token=employee_token,
    application_id="knowledge-assistant",
    documents=list(index.as_retriever().retrieve(question)),
    generate=lambda nodes: llm.complete(render_nodes(nodes)),
)
```

## Protect and Shadow modes

The Guard's policy mode is authoritative. In Protect mode unauthorized
resources are removed before generation and a failed Layer 2 check releases no
answer. In Shadow mode the Guard returns `would_allow`/`would_block` for
measurement; customers should still exercise the same adapter path before
enabling Protect. Streaming is not a safe release boundary unless the
application buffers the complete response first; the reference adapter
therefore advertises `streaming_release = false`.

## Identity and deployment responsibilities

The customer keeps its identity provider, RAG, vector store, and model. Guard
validates the employee token with OIDC/JWKS (static HMAC validation is for local
tests only), then evaluates the tenant-scoped policy synchronized from the
permission source. Keep Guard on the customer network or use the private
runner for private targets. Do not put employee or target credentials in
frontend configuration.


## Late cache/tool sources in Layer 2 (optional integration contract)

When a trusted RAG orchestration trace reports a source that was not part of
the initial Layer 1 retrieval, a strict source-set equality comparison would
incorrectly reject an employee who is actually authorized for the source.
AccessProof now supports **additional Layer 1 decisions for the same request**
without allowing arbitrary Layer 2 provenance to authorize itself.

The Python SDK accepts a `source_trace` callback (TypeScript: `sourceTrace`)
which runs **after generation but before response release** and must return
`RetrievedResource` entries from application-controlled tracing, including
cache/tool lineage. It must NOT infer sources from LLM text or self-reported
citations. The callback must include every source contributing to the answer.
The default SDK behavior without this callback remains unchanged, which means
that it cannot automatically detect uninstrumented cache/agent paths.

```python
from packages.rag_sdk import RetrievedResource

trace = []  # populated by the trusted RAG cache/tool/retriever instrumentation

response = protected_rag.run(
    employee_token=verified_employee_token,
    application_id="knowledge-rag",
    retrieved=initial_retrieval,
    generate=lambda authorized: generator_using_instrumented_tools(authorized, trace),
    source_trace=lambda: [
        RetrievedResource(
            source_id=item.source_id, resource_id=item.drive_file_id,
            chunk_id=item.chunk_id, derived_type=item.kind,
        )
        for item in trace
    ],
)
```

If sources in the trace are not in the original authorized set, the SDK sends
those sources to `/guard/v1/filter-resources` with the **same authenticated
employee/application/request**. An extra that is DENY/UNKNOWN blocks release in
Protect mode. Guard's `/guard/v1/check-output` accepts up to 16
`additional_decision_ids`, loads all one-time contexts with identity/request
binding, rechecks the latest installed policy for their union, and consumes
all decision contexts atomically. A subset of Layer 1's authorized resources
is valid output provenance; exact equality is **not** required.

**Security boundary:** This is a response-release safeguard, not a replacement
for preventing unauthorized cache/tool content from reaching the model. The
customer RAG must also intercept and authorize **every retrieval/tool/cache
input before its contents reach the LLM**. Source traces are trusted only if
generated by application-owned instrumentation, not user-controlled request
JSON or model-generated citations. When provenance is incomplete or cannot be
trusted, do not release the answer. Real customer framework/cached-tool
instrumentation and a live Google Drive integration must be validated before
claiming comprehensive provenance protection.
