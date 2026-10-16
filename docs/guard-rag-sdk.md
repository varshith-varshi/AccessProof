# Guard RAG integration

`packages.rag_sdk` is the framework-neutral reference integration for a customer RAG. It enforces this sequence:

```text
retrieve → Layer 1 → buffered model response → Layer 2 → release
```

Every retrieval result must have a stable `source_id` and `resource_id`. Protect mode does not release model output until Layer 2 approves it. Streaming generators are collected in a bounded in-memory buffer, so a blocked result releases no model tokens.

```python
from packages.rag_sdk import GuardClient, ProtectedRAG, RetrievedResource

guard = GuardClient("http://accessproof-guard:8080")
rag = ProtectedRAG(guard, max_response_bytes=1_000_000)

response = rag.run(
    employee_token=employee_access_token,
    application_id="employee-rag",
    request_id=request_id,
    retrieved=[RetrievedResource("sharepoint-source", "F123", "chunk-1", content="...")],
    generate=lambda authorized: llm.generate(authorized),
)
if response.response is None:
    raise PermissionError(response.reason)
return response.response
```

The employee token is never put in browser storage by this library. Keep the Guard on the customer-controlled network and pass tokens only over TLS. In production it validates employee tokens through OIDC discovery and JWKS, caches public key material locally, and refreshes JWKS once when an identity provider rotates to a new `kid`. Configure `ACCESSPROOF_GUARD_IDENTITY_MODE=oidc`, the issuer and audience, `ACCESSPROOF_GUARD_IDENTITY_TENANT_ID` for Entra-compatible tokens, and `ACCESSPROOF_GUARD_IDENTITY_SUBJECT_CLAIM=oid` when the policy uses Entra object IDs. `static` symmetric-key validation is for isolated local tests only.

Layer 2 contexts bind the application, stable subject, original request ID, and a five-minute expiry. They are consumed after one verification. For regeneration, perform a fresh Layer 1 check using only the already-authorized resources.
