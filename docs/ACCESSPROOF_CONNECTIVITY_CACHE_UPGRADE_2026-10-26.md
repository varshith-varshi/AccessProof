# AccessProof — Connectivity and Cache Discovery Upgrade

Date: 2026-10-26  
Scope: active `f15` repository, Gateway-only Google Workspace/Drive V1.  
Release status: **local implementation and tests; NOT customer-production certified**.

## What changed

This change builds on the existing control plane, customer-side Guard,
attested-manifest Gateway, read-only compatibility scanner, signed cache
authorization endpoint, and enrolled-machine challenges. It does **not** bring
back the retired general-purpose SDK or modify a production deployment.

### 1. Customer-side architecture inventory

`scripts/customer_architecture_inventory.py` is a read-only CLI to identify
possible components in an operator-approved customer RAG source directory.

Run from the AccessProof repository, on the customer-controlled machine:

```bash
python -m scripts.customer_architecture_inventory /path/to/customer-rag \
  --output ./accessproof-architecture.json
```

It reports bounded evidence for:

- LangChain/LangGraph, LlamaIndex, Haystack and Semantic Kernel hints.
- Redis, Memcached, PostgreSQL/SQLite, local Python cache, LangChain cache,
  semantic/GPTCache hints; multiple cache candidates can coexist.
- Qdrant, pgvector, Chroma, Pinecone, FAISS, Weaviate, Milvus and
  Elasticsearch/OpenSearch use hints.
- OpenAI-compatible, Anthropic and Gemini client hints.
- Docker Compose service/config and relevant model/cache images.
- Existing source compatibility scan findings: identity, routes, streaming,
  WebSockets, tools, worker paths, vector retrieval and direct model clients.

The result uses `accessproof.architecture_inventory/v1` and **always** sets
`certification_status: NOT_CERTIFIED`. Its `coverage` fields always remain
`NOT_VERIFIED`. It deliberately does not execute customer code, call endpoints,
use cloud credentials or expose env/config values. Observed file paths and
technology names are still metadata: obtain customer consent to retain or share
the report.

A parser dependency (`PyYAML`) is optional; if unavailable, Compose manifests
are marked unreviewed instead of silently treated as empty.

**Important:** `UNKNOWN` cache state means the inspector found insufficient
information. `NO_CACHE_DECLARED_UNVERIFIED` means an operator declared no
answer cache; it still does not demonstrate absence of hidden caches.
`CANDIDATES_FOUND_UNVERIFIED` is an inventory hint only, not interception.

### 2. Hardened cache identification during reference installation

`apps/gateway/accessproof_gateway/integration_wizard.py` now distinguishes:

- Configured Redis, Memcached, PostgreSQL and explicit `none`.
- Inferred technologies from a selected set of environment variable names.
- `unknown` when an approved no-cache declaration and recognized hints are absent.
- Competing cache-backend indications and contradictory no-cache assertions.
- Possible undeclared custom cache return paths.

Additional `plan` response fields:

```text
detected_cache_backend
cache_identification_confidence
cache_inventory_complete: false
cache_return_path_verified: false
blocking_issues
```

For a deliberately cache-free reference RAG, declare in its **customer-owned**
Docker Compose service labels:

```yaml
labels:
  com.accessproof.cache.mode: "none"
```

This is an operator assertion, **not** a runtime certificate. A cache-enabled
route still requires its signed-manifest return-path declaration and an
actual per-employee authorization check. Absence of a recognized cache variable
no longer silently means `none`. Unknown or conflicting states block staging.

### 3. Synthetic cache-return replay probe

`scripts/customer_cache_route_probe.py` checks exactly **one** customer RAG
cache-return path after the customer has approved a synthetic test.

It requires a private JSON config (0600), containing exactly:

```json
{
  "url": "http://127.0.0.1:8098/v1/protected-chat",
  "allowed_token": "REPLACE_WITH_SYNTHETIC_ALLOWED_EMPLOYEE_TOKEN",
  "denied_token": "REPLACE_WITH_SYNTHETIC_DENIED_EMPLOYEE_TOKEN",
  "request_body": {"message": "SYNTHETIC authorized test question"},
  "allowed_canary": "SYNTHETIC_ALLOWED_CANARY_ONLY",
  "forbidden_canary": "SYNTHETIC_FORBIDDEN_CANARY_ONLY",
  "cache_hit_field": "cache_hit"
}
```

The customer app must expose an authentic JSON cache-hit flag at the configured
field and support the same synthetic question/response for the test identities.
No real customer documents, live user tokens or private keys are appropriate.

```bash
chmod 600 ./synthetic-cache-probe.json
python -m scripts.customer_cache_route_probe \
  --config ./synthetic-cache-probe.json \
  --output ./cache-route-evidence.json
```

It makes three POST requests to a **literal loopback IPv4/IPv6 URL only**:

1. Authorized synthetic employee warms an approved canary answer (200).
2. Same employee repeats it and an actual cache-hit flag must be `true` (200).
3. Denied synthetic employee repeats the same request and must receive a denial
   (403) without either confidential/approved answer canary.

The private receipt contains hashes, statuses and bounded counts, not bearer
tokens or customer response bodies. A single failure fails the probe. A passing
receipt says `PASS_SINGLE_SYNTHETIC_CACHE_RETURN_ROUTE` and
`certification_status: NOT_CERTIFIED`; it **does not** prove complete cache
inventory, true Google Drive revocation latency, or untested application paths.

### 4. Web console

`web-v2/app/integrations/setup/page.tsx` now includes a local inventory report
preview under **Inspect your RAG, models and caches**. The file is parsed using
the browser file API: no report upload is sent to the AccessProof API. The UI
displays component hints, cache state, blockers and a prominent unverified
warning. The Verify stage also provides the synthetic cache replay CLI command.

## What is NOT solved by this change

The original connectivity/cache findings included **37** limitations or
validation gaps, not 37 software bugs. The new code addresses a subset:

| Area | Status after this change |
| --- | --- |
| Identify known cache technologies in customer source/Compose | Improved; read-only evidence only |
| Distinguish unknown cache from declared no-cache | Implemented in local inventory and guided preflight |
| Detect multiple/conflicting cache backends | Improved and block on conflicting guided configuration |
| Surface likely RAG, model, vector and alternate-route paths | Improved static inventory; false negatives remain possible |
| Preview findings in onboarding | Implemented with local, non-upload file preview |
| Test unauthorized cached answer reuse on one synthetic route | Implemented, opt-in, local-only |
| Automatically enumerate every runtime cache/route | **Not implemented** |
| Transparently intercept caches from arbitrary RAG frameworks | **Not implemented** |
| Kubernetes/serverless installer/cutover | **Not implemented** |
| Universal LangChain/LlamaIndex/Haystack live integration | **Not implemented** |
| WebSocket/native incremental streaming/tool/background results | **Not supported for universal Protect** |
| Autodetect every model endpoint and vendor-specific protocol | **Not implemented** |
| Automatic Guard-enrollment-triggered system-wide security tests | **Not implemented**; customer-approved tests remain separate |
| Live customer Google Workspace/Drive and revocation timing | **Not validated by this change** |
| Full customer-app route certification or arbitrary pipeline bypass guarantee | **Not established** |

Even the strongest static signals or a passing synthetic cache replay cannot
justify a claim that every deployment route is protected. Keep the existing
control-plane Protect preflight, separate admin approvals, signed source
provenance, and live Guard-audited route cutover.

## Testing

New regression files:

- `tests/unit/test_customer_architecture_inventory.py`
- `tests/unit/test_customer_cache_route_probe.py`

Existing tests extended:

- `tests/unit/test_gateway_integration_wizard.py`
- `web-v2/e2e/web-v2.spec.ts`

Tests include absent cache configuration, conflicting declarations, multiple
backend inventory, malformed Compose, no secret disclosure, no target code
execution, cache hit evidence, cross-employee answer isolation, escaped JSON
canary detection, strict loopback URL restrictions, private config permissions,
and desktop/mobile local JSON preview.

The implementation deliberately leaves the original Gateway, Guard, Google
Drive connector, and live production system untouched.

## Next acceptance requirements

Before a real customer Protect assertion, require:

1. Reviewed inventory **and** a complete inventory of response endpoints,
   async workers, caches, agent tools and alternate LLM clients.
2. Working per-customer trusted retrieval signatures and verified OIDC mappings.
3. Signed-cache reauthorization for each supported answer-return route.
4. Independent synthetic allow/deny, revoked-user, cache-reuse and alternate-route
   tests through the actual employee-facing endpoints.
5. Network isolation and actual egress testing, not only static Compose labels.
6. Live Google Workspace permission-change timing, failure handling and rollback.
7. A per-route scope statement listing *excluded* or untested customer paths.

No production deployment, source switch or authorization bypass is undertaken
by these diagnostic tools.

## Completed verification (2026-10-26)

- Broad Python unit/integration/security run: **exit 0, all collected tests passed**.
  That run began before the final two inventory hardening cases were added.
- Current Python unit/integration/security collection: **1,021 tests**.
  The two newly added cases also **passed separately**, yielding full local
  coverage of the current collection without rerunning the lengthy entire suite.
- Focused inventory, compatibility-scanner, cache-route and installer suite:
  **46 cases passing** before the final two scanner-hardening cases.
- Python Ruff: **all touched source/test modules pass**.
- Frontend TypeScript, ESLint, optimized production build: **pass**.
- Browser E2E: **33 passed, 5 skipped** in a serial full run. The initial
  concurrent browser run had two timeout failures in unrelated Guard/Employee
  pages; both passed when rerun serially and the subsequent entire browser
  suite passed.
- Real loopback HTTP CLI smoke using an ephemeral synthetic cache-response
  server: **PASS_SINGLE_SYNTHETIC_CACHE_RETURN_ROUTE** with **NOT_CERTIFIED**.
- No production deployment, no repository reset, and no Git commit was made.

Passing local tests do not establish live Google Workspace, arbitrary customer
cache-route coverage, or production authorization correctness.
