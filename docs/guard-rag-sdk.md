# Guard RAG integration

`packages.rag_sdk` is the framework-neutral reference integration for a customer RAG. It enforces this sequence:

```text
retrieve → Layer 1 → buffered model response → Layer 2 → release
```

Every retrieval result must have a stable `source_id` and `resource_id`. Protect mode does not release model output until Layer 2 approves it. Streaming generators are collected in a bounded in-memory buffer, so a blocked result releases no model tokens.

For framework integration, use the adapters in `packages.rag_sdk.adapters`.
`LangChainAdapter`, `LlamaIndexAdapter`, and `HaystackAdapter` accept the
framework's document objects and pass only Layer 1-authorized originals to the
generator. See [the adapter contract](rag-adapter-contract.md) for the stable
metadata rules and the support boundary. A framework is not considered
protected merely because it can produce text or citations: it must expose a
trusted retrieval hook and allow the response to be buffered for Layer 2.

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

## Source content attestation and certification eligibility

Layer 1 authorizes *metadata* (`source_id`, `resource_id`, `chunk_id`). Metadata
alone cannot prove that the bytes the application hands to the model are the
bytes AccessProof ingested under that identity. An application — or a
compromised retrieval layer — can keep an authorized resource ID and swap the
content, the version, or the text of another tenant's document.

`ProtectedRAG` therefore fails closed. A Protect release requires a pinned
`SourceAttestationVerifier`:

```python
from packages.rag_sdk import GuardClient, ProtectedRAG
from packages.rag_sdk.attestation import SourceAttestationVerifier

verifier = SourceAttestationVerifier(
    tenant_id=organization_id,
    trusted_keys={ "ingester-2026-q4": trusted_public_key },  # public keys only
    revoked_key_ids={"ingester-2026-q2"},                      # rotation history
)
rag = ProtectedRAG(guard, provenance_verifier=verifier)
```

Each retrieved resource carries an Ed25512 attestation signed by a trusted
ingestion worker, binding tenant, application, source, resource, chunk, revision
and the SHA-256 digest of the exact content, with issue/expiry inside a
one-hour window. Verification runs before generation for content and again
against the Layer 2 source trace, so a forged ID, modified bytes, a wrong
version, an expired token, an unknown or revoked key, or a missing attestation
all block before any model token is produced. The response reports
`provenance_level` (`SOURCE_ATTESTED`) and `certification_eligible=True`.

Only a separately trusted provider-ingestion worker holds the private key. The
customer RAG application pins public keys and can never mint its own
attestations. An attestation over attacker-supplied data would still only prove
that the signer signed it, so key custody belongs to the ingestion pipeline, not
the app.

Without a verifier, Protect returns `block` /
`SOURCE_CONTENT_ATTESTATION_REQUIRED` before generation and Layer 2 is never
called. Legacy integrations that only have authorized metadata must opt in
explicitly:

```python
rag = ProtectedRAG(guard, allow_unattested_metadata=True)
```

That mode is mutually exclusive with a verifier, and every response it produces
is labelled `provenance_level="UNATTESTED_METADATA_ONLY"` with
`certification_eligible=False`. Do not use it as a fallback to make a certified
route pass; the label is the reason a route is not certifiable.

The same rule applies to signed answer caches: a cache hit is only released when
a verifier is pinned and every dependency digest in the manifest re-checks,
otherwise it blocks with `CACHE_MANIFEST_BINDING_REQUIRED` or
`CACHE_MANIFEST_INVALID` before the Guard is reached.

The TypeScript SDK in `packages/rag-sdk-typescript` mirrors this contract: the
constructor is `new ProtectedRAG(guard, maxResponseBytes, provenanceVerifier?,
allowUnattestedMetadata?)`, verification uses WebCrypto Ed25519, and responses
carry `provenanceLevel` and `certificationEligible`.


## Protect certification and status

The cloud API requires three separate recent, machine-audited test request IDs:
an allowed Layer 1/Layer 2 request, a denied Layer 1 request, and a Layer 2
provenance rejection. Operators must also explicitly attest that their own
RAG buffers model output before release; Guard audit alone **cannot** prove
that the customer always used the adapter or that its output was buffered.
The endpoint rejects checkbox-only attestations and Protect cannot be enabled
without the other source, identity, policy, and Guard-health readiness checks.
After requesting Protect, the application is `protect_pending` until the
enrolled Guard returns an authenticated heartbeat confirming Protect for that
application. The UI must not claim "Protect" while pending.

The customer's existing `/v1/chat` demo route simulates stale access control
and is disabled by default. Use `/v1/protected-chat` with a valid employee OIDC
JWT, source ID and application ID to test actual Guard calls. Do not expose the
legacy route in a customer production deployment.

Build the Guard installer with `bash scripts/build-guard-package.sh` before
building the API Docker image. Signed/authenticated web-v2 sessions may
download the generated archive through `/api/v1/guards/download`. The installer
contains customer-side Python source; do not represent it as tamper-proof or
source-hidden. Check the SHA-256 sidecar before distributing a release.
