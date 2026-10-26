# AccessProof RAG SDK for TypeScript

This private, unpublished SDK implements the same two-layer `accessproof.rag/v1`
contract as the Python SDK. `ProtectedRAG` filters retrieved resources through
the customer-side Guard before generation, buffers the response, verifies
trusted provenance, and releases text only after Layer 2 allows it.

The application must supply the employee's real bearer token and stable
source/resource metadata. Never substitute an email field or an untrusted
`X-User-ID` header for verified identity.

```ts
const guard = new GuardClient({ baseUrl: "http://accessproof-guard:8080" });
const rag = new ProtectedRAG(guard);
const adapter = new LangChainAdapter(rag, "google-drive-source-id");

const result = await adapter.run({
  employeeToken: requestEmployeeToken,
  applicationId: "finance-rag-prod",
  documents: retrievedDocuments,
  generate: authorizedDocuments => chain.invoke({ documents: authorizedDocuments }),
});
```

Do not stream model bytes directly to the user before this call resolves.
