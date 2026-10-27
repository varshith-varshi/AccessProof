# AccessProof V3 cache-protection contract

AccessProof does not read arbitrary customer cache storage. A protected customer
route supplies a cache hit to its local RAG integration together with a signed
`CachedAnswerManifest`. The cache itself can be Redis, an in-memory cache, or a
database; authorization occurs at the route that would deliver the answer.

## Cache-write boundary

Only a trusted, customer-controlled generation/cache-write service may issue a
manifest. It signs the exact answer digest and the complete list of source
resource dependencies. Each dependency includes its source ID, resource ID,
chunk ID, content version, content digest, and the existing short-lived source
attestation. The private cache-manifest signing key must not be available to
the model, browser, vector store, or employee client.

## Cache-hit boundary

For every cache hit, `ProtectedRAG.verify_cached_answer`:

1. verifies the cache manifest signature, expiry, tenant, application, answer
   digest, producer identity, and an unambiguous complete dependency list;
2. verifies every dependency against the pinned source-attestation key and its
   original content digest, without loading document text into the answer path;
3. calls Guard Layer 1 for the employee making this request;
4. requires an exact allow for every dependency; and
5. calls Guard Layer 2 before returning the answer.

A missing, expired, forged, cross-tenant, cross-application, altered, or
incomplete manifest is blocked. A previously authorized employee's cache entry
is never reused as an allow decision for another employee. A Layer 1/2 block
returns no answer and never invokes a model or automatic regeneration.

## Supported cache categories

The same dependency model covers document chunks, retrieval-result references,
trusted tool output, and conversation memory only when those inputs have
source attestations. Generated answers use `CachedAnswerManifest`. Opaque
provider model caches and arbitrary cache entries with no provenance boundary
are not protected or certified by this contract.

## Integration requirements

The RAG route must retain the manifest beside the cached answer and invoke the
SDK on every delivery. Configure a `SourceAttestationVerifier` and a distinct
`CachedAnswerManifestVerifier` with pinned public keys for the same tenant.
The integration must use Guard Protect mode, must not stream before Layer 2,
and must fail closed if the Guard or verification is unavailable.

The generic Gateway protects its documented attested retrieval route. It does
not claim to discover an application's private answer cache automatically;
applications must explicitly call the SDK cache-hit boundary until a supported
cache adapter is installed.
