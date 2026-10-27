# Gateway security boundaries

The certified Gateway boundary owns the complete model prompt: trusted operator instruction, attested authorized enterprise context, and clearly labelled untrusted employee text. It cannot certify hidden context that bypasses its request contract. Cache, tool, assistant-memory, developer, and system inputs must be supplied as independently attested resources or are rejected.

It verifies Guard Layer 1 before model invocation and Layer 2 after the fully buffered model response. No streaming is supported because released bytes cannot be recalled.

## Local code hardening — 2026-10-23

* HTTP request bodies are size-checked incrementally, including when there
  is no trustworthy `Content-Length`.
* Upstream LLM responses are collected through a byte-bounded streaming
  reader before JSON decoding and Layer 2 verification; unbounded
  `httpx.post(...).content` buffering was removed.
* The Gateway rejects unauthenticated HTTP requests before parsing the
  protected request schema. Privileged model roles remain server-controlled.
* Layer 2's Gateway-owned trace includes **only documents actually admitted
  into generation**. Denied retrieval candidates are not falsely classified as
  model-used late sources.
* Google Drive trusted ingestion checks root membership, file revision,
  deletion, content type and file size, then reads provider text under
  authenticated OAuth and signs it outside the retrieval component.
* A customer-provided claim `provider_identity_verified=True` remains
  insufficient evidence unless it was constructed inside that trusted source
  ingestion boundary.
* Signed source content cannot prove arbitrary uninstrumented customer RAG
  tool, cache, memory or direct-model paths. Protect certification still
  requires deployment-specific route proof and cannot be inferred from
  installer configuration labels.

The new local installer is a **staging utility**, not a deployment
certification authority.
