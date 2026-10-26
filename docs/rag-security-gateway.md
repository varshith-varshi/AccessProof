# AccessProof RAG Security Gateway

The Gateway is a customer-side HTTPS boundary for a **configured retrieval API
pattern**. It does not claim to secure an arbitrary RAG just by sitting in
front of its model endpoint. A reverse proxy cannot see undocumented vector,
cache, agent-tool, or prompt inputs.

## What the supported route verifies

`POST /v1/chat/completions` accepts the employee's `Authorization: Bearer`
token and an attested retrieval manifest. It:

1. sends the retrieved resource IDs to the enrolled local Guard (Layer 1);
2. verifies an independent ingester's Ed25519 attestation over each exact
   source/resource/chunk/revision/content byte sequence;
3. builds model context only from Guard-authorized resources;
4. buffers the complete upstream OpenAI-compatible model response; and
5. performs Guard Layer 2 provenance/revocation validation before it returns a
   single response byte.

The model receives no denied resource content. A Guard, attestation, upstream
model, malformed response, or provenance failure is fail-closed.

## Deployment

Build the image from this repository, copy `packaging/gateway/compose.yml` and
`.env.example` into a customer-controlled directory, then set the five required
environment values. The attestation key map contains **public** keys only; the
source ingester retains private signing keys. Bind the local port to loopback
and let the customer's authenticated reverse proxy expose it if needed.

The RAG's configurable retrieval path must send the stable source/resource/
chunk IDs, content revision, exact retrieved text, and trusted attestation to
the Gateway. Point its model-completion URL at this Gateway route only after
the Gateway health check and an allow/deny/provenance challenge pass.

## Protection status

An installed Gateway is `INSTALLED_UNVERIFIED` until a deployment proves the
three real-route challenges: authorized allow, revoked/denied block, and
provenance block. It is not correct to label a generic OpenAI proxy or a model
base URL alone as protected. Streaming is deliberately rejected on this route:
Layer 2 cannot retract bytes already sent to an employee.

## Supported versus unsupported

Supported: the AccessProof attested retrieval-manifest contract with an
OpenAI-compatible non-streaming model endpoint. Unsupported: opaque third-party
RAGs, hidden retrieval/tool paths, unsigned document metadata, response
streaming, and any deployment that cannot prove source trace completeness.
