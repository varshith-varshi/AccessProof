# Gateway customer validation

Validate an allow, denied-resource, revocation, forged-attestation, Layer 2 denial, Guard-outage, and alternate-path case against the deployed customer route. Record Guard audit IDs, source freshness, deployment configuration fingerprint, and measured revocation delay. Do not mark an application protected based only on Gateway health or a browser checkbox.

## Restricted local diagnostic challenge (2026-10-23)

The repository includes a **customer-side, loopback-only, diagnostic** agent.
It is not a Protect certificate and must never satisfy the production
`CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED` control by itself.

```bash
chmod 600 /secure/reference-challenge.json
python -m apps.gateway.accessproof_gateway.challenge_cli \
  --config /secure/reference-challenge.json \
  --output /secure/reference-challenge-results.json
```

The private JSON configuration has this structure (these placeholders are
not valid synthetic credentials or source signatures):

```json
{
  "url": "http://127.0.0.1:8090/v1/chat/completions",
  "application_id": "your-registered-reference-app",
  "challenge_nonce": "UNPREDICTABLE_RANDOM_NONCE_AT_LEAST_32_CHARACTERS",
  "allowed_canary": "SYNTHETIC_ALLOWED_OUTPUT_CANARY",
  "forbidden_canary": "SYNTHETIC_DENIED_OUTPUT_CANARY",
  "probes": [
    {"name": "allow", "employee_token": "AUTHORIZED_SYNTHETIC_JWT",
     "retrieved_resources": [], "expect_status": [200],
     "must_contain": "SYNTHETIC_ALLOWED_OUTPUT_CANARY"},
    {"name": "deny", "employee_token": "DENIED_SYNTHETIC_JWT",
     "retrieved_resources": [], "expect_status": [403]},
    {"name": "tamper", "employee_token": "AUTHORIZED_SYNTHETIC_JWT",
     "retrieved_resources": [], "expect_status": [503]},
    {"name": "layer2_revoke", "employee_token": "AUTHORIZED_SYNTHETIC_JWT",
     "retrieved_resources": [], "expect_status": [403]}
  ]
}
```

Replace the empty resource arrays with **actual signed synthetic chunks** from
the approved, disposable test source. An empty resource array will fail the
diagnostic preconditions. Deny must produce `NO_AUTHORIZED_RESOURCES`,
tamper must produce `SOURCE_CONTENT_ATTESTATION_FAILED`, and an in-flight
revocation must produce `LAYER2_ACCESS_REVOKED`. A generic 503 from an
unavailable Guard is *not* evidence of an authorization denial.

Before running `layer2_revoke`, the disposable synthetic model or test
fixture must be configured to revoke the approved source permission **after
Layer 1 approval but before Layer 2 evaluation**. This configuration is
intended for a dedicated isolated test environment; do not mutate permissions
in a real customer's production document library.

The agent verifies:
- The Gateway is ready before and after the synthetic test run.
- The actual HTTP response bytes contain no forbidden canary.
- Failure cases return the exact security-layer refusal codes.
- The allowed response includes a Guard decision ID and a positive Protect
  decision.
- The tested route is a local loopback endpoint, not an arbitrary internet URL.
- The resulting report is written once with private mode-0600 permissions.

The agent **cannot** prove that an unrelated customer RAG routes all
retrieval, tools, caches, model fallbacks and responses through AccessProof,
or that provider and employee identities are production-authentic. A
production challenge agent must be enrolled, tied to a deployment fingerprint,
correlated with authenticated Guard audit events and provider-backed source
authorization, checked for alternate paths, and acknowledged by the Guard.

Do not enable Protect based on this local result.

## Two-stage customer-side Gateway Protect reference workflow (Oct 23, 2026)

**Supported reference target:** a customer-authorized Docker Compose deployment
with an independently enrolled **in-stack** Guard, a signed-source retrieval
contract, a real employee bearer-JWT boundary, an isolated customer RAG network,
a different isolated **in-stack** model-service network, and a loopback-published
customer RAG `/v1/chat/completions` route. External models, custom apps
without this interface, native Docs indexing, arbitrary tools/caches and
unbounded RAG framework plugins are **not** certified by this workflow.

### 1. Generate and review the files; do not change RAG traffic

```bash
python -m apps.gateway.accessproof_gateway.installer \
  --spec /secure/customer-gateway-spec.json \
  --compose /customer/docker-compose.yml \
  --output /secure/accessproof-generated
```

The customer approves the staging outputs (`installation.json`,
`gateway.override.json`, `gateway.env`). Private files are mode 0600.
The staged manifest now fingerprints the original Compose + staged override
and pins the exact Gateway loopback route. Nothing is deployed in this step.

### 2. Install Gateway, not RAG: explicit local approval

```bash
python -m apps.gateway.accessproof_gateway.installer \
  --spec /secure/customer-gateway-spec.json \
  --compose /customer/docker-compose.yml \
  --output /secure/accessproof-generated \
  --apply-staged
```

`--apply-staged` verifies unchanged inputs, private file permissions,
tenant/app/Guard/model fields, and deployment hashes before building and
starting **only** the Gateway. It refuses to overwrite a running Gateway and
never redirects the customer RAG. `--apply` can instead stage *and* start
the Gateway in a single command when `--output` is a new directory.

**Do not use `docker compose down` to recover.** The installer only attempts
Gateway-specific rollback if its new installation fails.

### 3. Customer console: issue the bounded reference challenge

From **AI applications → Set up Gateway**, upload the non-secret
`installation.json` manifest to populate its hashes. Issue the 10-minute
server nonce; record the challenge ID securely. Configure a disposable
test source with signed source chunks, a verified allowed synthetic employee,
a verified denied synthetic employee and a separate isolated revocation test
fixture. The browser does **not** take OAuth or JWT secrets.

Save an owner-reviewed **mode-0600** `reference-challenge.json` with the
`challenge_id`, exact nonce and four synthetic signed resource probes. The
`url` must be the Gateway's approved loopback route. There are no manually
entered retrieval request IDs; the machine derives them from the nonce.

### 4. Machine-observed Gateway/Guard reference tests

```bash
python -m apps.gateway.accessproof_gateway.customer_agent \
  --installation /secure/accessproof-generated/installation.json \
  --spec /secure/customer-gateway-spec.json \
  --challenge /secure/reference-challenge.json \
  --guard-credentials /secure/guard/credentials.json \
  --output /secure/reference-test-receipt.json
```

This runs four local HTTP challenges and checks real response bytes; requires
specific reasons for denial, tampered attestation and in-flight revocation;
refuses an unavailable Guard, Shadow verdict or insecure Docker route; and
submits **only metadata** to the API using the customer's enrolled Guard
credential. The backend independently matches uploaded Guard audit events,
policy version, source, tenant, application, and one-time nonce. The result is
`tested_awaiting_customer_cutover`, **not an active Protect claim**.

### 5. Explicit operator-approved RAG routing cutover and separate proof

Prepare a **mode-0600** `employee-route-probe.json` with *exact* keys:
`url` (loopback-published customer RAG `/v1/chat/completions` URL),
`allowed_token`, `denied_token`, `allowed_resources`,
`denied_resources`, `allowed_canary`, and `forbidden_canary`.
These are **synthetic/test** signed source chunks and identities only.
The customer RAG contract must accept the tested request envelope and
preserve the Gateway's `accessproof.decision` and `decision_id` metadata.

```bash
python -m apps.gateway.accessproof_gateway.customer_cutover \
  --installation /secure/accessproof-generated/installation.json \
  --spec /secure/customer-gateway-spec.json \
  --challenge /secure/reference-challenge.json \
  --guard-credentials /secure/guard/credentials.json \
  --employee-route-probe /secure/employee-route-probe.json \
  --output /secure/customer-cutover-receipt.json \
  --approve-route-cutover
```

This is **not** an unattended cloud operation. The explicitly approved
customer-side command verifies a prior server-reported reference test and
current Gateway/Guard readiness; then runs `docker compose up -d --no-deps
--no-build <selected-rag>` with the reviewed routing override. It tests
an allowed employee, a distinct denied employee, and an explicitly forged
source-content request **through the actual customer RAG HTTP endpoint**,
not through the Gateway alone. At least one allowed chunk must carry a real
provider/source attestation so tampering its content invalidates the signature. The backend
requires fresh, matching Guard Layer 1/2 audit events for the positive
request, Layer 1 block evidence for the negative request, and a Guard Layer 1
allow record for the forged-content request followed by an attestation failure. Without those
events, the control plane will not mark `cutover_verified`.

If the route verification fails **after** the RAG restart, the command
attempts to **stop only that RAG service**. It does not silently fall back
to unprotected direct-model traffic. The operator must inspect the
customer's service and restore service only after protection is safe.
This can intentionally cause an outage if verification fails.

### 6. Protect activation requires separate Guard acknowledgment

The API issues no production certificate from the installer alone. The
readiness checklist still requires source connection health, fresh ACL and
directory policy sync, an enrolled non-revoked Guard, a verified employee
identity path, machine challenge evidence, verified real RAG cutover and
Guard-reported Protect mode. The test result itself is **explicitly marked
`production_certification: false`** because real provider/identity and
alternate-route validation are still environment-specific.

**Current product limitation:** This is a controlled, reference-stack
integration workflow. It is not universal one-click support for arbitrary
LangChain, LlamaIndex, cache/tool, Kubernetes, Microsoft, Claude or Gemini
deployments. The existing Python/TypeScript SDKs are still present and
unchanged by this optional integration path.

## Machine-bound reference Gateway verification and Protect activation

The application console now supports **AI applications → Set up Gateway** for
an application registered with the `accessproof-gateway` adapter.

This is a **supported reference route**, not an automatic interceptor for an
arbitrary proprietary RAG. A customer-side Guard must already be enrolled and
be synchronizing policy, directory mappings and source permissions.

**Exact reference deployment compatibility:**

- Customer-managed Docker Compose deployment with source code that already
  supports the `accessproof.gateway/v1` attested retrieval contract and a
  configurable protected chat URL.
- Customer-side RAG and Gateway on an **internal** application network;
  self-hosted model service on a separate internal network accessible only by
  the Gateway; model ports must not be externally published.
- No privileged/host-networked application containers, Docker socket mounts,
  or direct model-network access from the customer RAG.
- Google Drive is the initial enterprise source. The local text ingestion
  CLI supports authenticated, signed `text/plain` documents only.
- Actual employee identities must be verified by the enrolled Guard and
  mapped to the source identity. Unknown mappings fail closed.
- Four disposable synthetic identities/permissions challenge outcomes can be
  issued: allow, deny, forged attestation, revoke during generation.

The initial Gateway installer stages a deployment override and records
`deployment_sha256` and `route_sha256` in a mode-0600
`installation.json`. Starting the Gateway with `--apply` **does not**
route any customer traffic through the Gateway.

### Step A: Issue a challenge

Use the dashboard's new Gateway setup panel to upload the installation
manifest. The control plane returns a nonce and challenge ID scoped to this
specific tenant/application/Guard/source/deployment/route/policy revision.

```text
POST /api/v1/current/ai-applications/{app}/protection/challenge
{
  "deployment_sha256": "<from installation.json>",
  "route_sha256": "<from installation.json>"
}
```

The challenge nonce is returned once. The operator combines it with four
signed synthetic test resource manifests and four **synthetic employee**
identity tokens into a private mode-0600 JSON challenge configuration.

### Step B: Enrolled machine verification

Run on the **authorized customer Docker host**:

```bash
python -m apps.gateway.accessproof_gateway.customer_agent \
  --installation /secure/accessproof-generated/installation.json \
  --spec /secure/gateway-spec.json \
  --challenge /secure/customer-challenge.json \
  --guard-credentials /var/lib/accessproof-guard/credentials.json \
  --output /secure/reference-probe-result.json
```

The agent checks its local reference Docker Compose egress topology and
original-file hashes, runs all four HTTP challenges through a real Gateway,
then submits result digests from the enrolled Guard credential. The
control plane **independently** checks matching Guard audit events for the
nonce-derived request IDs and exact Layer 1/2 results. If the Guard audit
service has not uploaded the events yet, the operator must ensure it syncs
before repeating the submission.

A passing result means **REFERENCE ROUTE TESTED**. It does **not** enable
Protect on the customer's RAG or establish production accreditation.

### Step C: Explicit customer RAG cutover and retest

Use a customer-authorized, supported isolated reference Compose deployment
and ensure the RAG's *real employee-facing* loopback endpoint is available.

```bash
python -m apps.gateway.accessproof_gateway.cutover_cli \
  --installation /secure/accessproof-generated/installation.json \
  --spec /secure/gateway-spec.json \
  --challenge /secure/customer-challenge.json \
  --guard-credentials /var/lib/accessproof-guard/credentials.json \
  --application-url http://127.0.0.1:18155/v1/chat/completions \
  --output /secure/cutover-result.json \
  --approve-customer-rag-restart
```

This makes an **explicitly authorized change** to the selected customer RAG
service via Docker Compose and uses the protected route. It executes
post-cutover positive, denial, and forged-document HTTP tests. The enrolled
control-plane agent must find distinct machine-authenticated Guard audits for
all required paths, including a Layer 2 positive allow and Layer 1 denial and
signed-attestation rejection. Only then can the control plane mark the
reference route `cutover_verified`.

The cutover CLI fails closed by **stopping the selected customer RAG
service** when post-cutover checks fail. It does not silently restore a
potentially unprotected direct-model route. Operators need explicit change
control, an independently verified safe recovery plan, and application
health checks outside this limited workflow. If the RAG cannot be stopped,
immediate operator intervention is required.

### Step D: Enrolled Guard acknowledgment

The last Guard heartbeat must report the same application in Protect mode
with a recent, healthy policy version and required source readiness. Only
then can the application dashboard display Protect. Any missing permission
synchronization, identity mapping, source/Guard health, stale configuration
fingerprint, or failed challenge prevents activation.

### Important security limitations

**This is not a general-purpose one-click SaaS integration**. It requires
a supported configurable customer RAG that already respects the certified
retrieval contract and protected response boundary. The installer cannot
add those internal interception points to arbitrary customer software.
Static Docker network checks cannot prove that no undocumented in-process
route, cache, custom model client or background worker bypasses enforcement.

The current reference two-stage mechanism does **not** provide a production
certificate. It uses a customer-owned machine reporting certain isolation
properties; broad enterprise certification still needs an independently
validated network/ingress/egress boundary, actual provider-backed permission
and employee identity test, and real customer environment verification.

Do not give a production Protect claim to a generic custom RAG based solely
on these local reference checks.
