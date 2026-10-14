# AI target integration

AccessProof does not assume one RAG endpoint shape. `GenericHttpTarget` supports a configured method, JSON body, static headers, bearer/API-key credentials and dot-path extraction for answer, citations, retrieved documents and tool outputs.

Allowed template variables are intentionally constrained:

```json
{
  "message": "{{ probe }}",
  "user_id": "{{ principal.external_id }}"
}
```

Arbitrary template code is rejected. Identity mapping must reflect real authorization: passing an email is valid only if the customer AI actually treats that field as an authenticated identity. JWT/cookie/custom identity adapters remain future work.

Cloud mode blocks private network destinations. Use private runner mode for internal DNS, private IPs and mTLS-style integrations.
