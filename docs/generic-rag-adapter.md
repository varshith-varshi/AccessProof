# Generic HTTP RAG adapter

AccessProof's generic HTTP target is executed by the private runner. It supports
customer-private destinations without putting target credentials in the browser.

## Basic bearer-token target

Configure an AI target with a private-runner endpoint such as
`https://rag.example.internal/chat`, method `POST`, and body:

```json
{"question":"{{ probe }}"}
```

Configure the header template:

```json
{"Authorization":"Bearer {{ principal.access_token }}"}
```

For a response such as:

```json
{"answer":"...","citations":["document-1"],"retrieved_documents":[{"content":"..."}]}
```

use these mappings:

```text
answer: answer
citations: citations
retrieved documents: retrieved_documents[].content
tool outputs: tool_outputs[].content
```

The safe template variables are `{{ probe }}`, `{{ principal.external_id }}`,
`{{ principal.email }}`, `{{ principal.access_token }}`, and `{{ session.id }}`.
Unsupported expressions are rejected; templates are not evaluated as Python or
Jinja code.

## API key and custom identity headers

Store a target API key through the target credential form. The runner can inject it
as `Authorization: Bearer …` or a configured API-key header. Combine this with safe
identity headers, for example:

```json
{
  "X-API-Key":"configured by target credential",
  "X-User-Email":"{{ principal.email }}",
  "X-User-ID":"{{ principal.external_id }}"
}
```

Identity-specific bearer tokens remain in the encrypted Alice/Bob test-identity
records and are never returned by the API.

## Sessions and evidence

Use `STATELESS` when possible. `NEW_SESSION_PER_PROBE` requires a configured
session-create endpoint, `ONE_SESSION_PER_RUN` reuses one created session, and
`CUSTOM_SESSION` requires the caller to supply a session ID. Browser automation or
interactive SSO is not supported by this adapter.

AccessProof checks the final answer, citations, retrieved documents, and tool
outputs for the exact synthetic canary, resource identifier, and protected value.
A clean final answer is not sufficient if a retrieved chunk still contains the
canary.

Cloud targets must use HTTPS and a globally routable hostname. Private runners may
call customer-approved internal destinations; redirects are disabled and response
timeouts are enforced.
