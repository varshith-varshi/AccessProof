# Local adversarial review — 23 October 2026

## Scope

This review used only the disposable local test database, synthetic identities,
mock provider endpoints, and loopback TCP services. It did not contact a
production deployment, customer account, or real cloud provider.

## Confirmed findings fixed

1. **Ambiguous enforcement-request fields** — Gateway and Guard boundary models
   could silently discard unknown nested fields. This allowed different
   components in a customer stack to interpret a request differently. The
   protected Gateway request, Guard setup request, Layer 1 request, Layer 2
   request, resources, and provenance items now reject unknown fields.
2. **Weak static HMAC identity configuration** — Guard static HS256 mode
   accepted a verification secret shorter than the 32-byte minimum recommended
   for HS256. Guard now fails closed with `IDENTITY_STATIC_KEY_UNSAFE` before
   processing the token.
3. **Order-dependent local route test** — a stale module-level test diagnostic
   could make the real-TCP Gateway test fail when it followed an unconfigured
   test Guard. The test harness now establishes its own healthy diagnostic
   state, matching a successful control-plane sync.

## Attacks exercised

- Tenant, source, application, and subject confusion
- JWT algorithm, issuer, audience, expiry, tenant, and JWKS/SSRF attacks
- Layer 1/Layer 2 contradictions, replay, duplicate grants, policy revision
  races, revocation during generation, and stale policy/source health
- Document metadata alias collisions, mutable retriever objects, late cache or
  tool sources, vector-content substitution, forged/expired/wrong-bound
  attestations, and provenance omissions
- Prompt/system/developer/tool-context injection through the Gateway contract
- Response buffering, oversized payloads, malformed Guard/model replies, and
  no-release behavior after a Layer 2 block
- Google Drive source-boundary, revision-race, Unicode, provider-size, and
  MIME-type checks

## Evidence

- Python suite: `553 passed, 1 xfailed`
- TypeScript SDK: `34 passed`
- web-v2 lint, typecheck, and production build: passed
- Customer simulation stages: passed with synthetic sources, local TCP, and
  mock providers
- Gateway/Guard/Drive-RAG Compose configuration: passed

## Remaining boundaries

The expected failure is the legacy metadata-only SDK route. It is intentionally
not eligible for certified Protect operation; signed source attestations are
required on the Gateway route.

This review cannot prove a customer has routed every RAG, cache, tool, or
model path through AccessProof. It also does not replace validation against a
real configured Google Workspace/Microsoft tenant, customer OIDC issuer, and
customer RAG deployment. Those must be performed before production protection
claims.
