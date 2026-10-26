# Guided customer-side RAG integration (reviewed Docker reference contract)
Date: 2026-10-24

**Release status: Locally implemented and tested on reference layouts.**
**This is not universal no-code one-click integration of arbitrary RAG systems.**

The AccessProof web console now has **Integrations → Guided RAG connection**
at `/integrations/setup`. It guides an administrator through selecting a
supported answer cache, registering the source/application/Guard, and the
customer-host installation and verification commands. It does not control
customer Docker hosts remotely and never asks for provider or machine secrets
in the browser.

The local `apps.gateway.accessproof_gateway.integration_wizard` orchestrates
already audited components: approved Gateway installer, machine-attested
reference challenges, authenticated Guard audit receipts, customer route
cutover and the existing control-plane Protect preflight. No source-code edits
to the original customer's RAG are made by the installer. A compatible RAG
**must already implement the declared source-attested Gateway route
interface** and use the approved routing environment variable.

## What is actually automated?

* Parse a customer-owned, mode-0600 installation spec.
* Ask Docker Compose to resolve its topology (without running containers).
* Inspect reviewed route-contract labels, source/Guard/model network isolation,
  and the selected Redis/Memcached/PostgreSQL cache path. Missing signed-cache
  return-path declarations, direct model access or unknown cache modes block.
* Stage a customer-private mode-0700 output directory, mode-0600 Gateway
  secret file, immutable reviewed Compose override and SHA-256 deployment/
  route binding. **Never overwrite or edit the original Compose file**.
* With explicit owner approval, install only the Gateway container, check its
  actual loopback HTTP liveness, and roll back a newly created Gateway if
  its installation fails. No RAG traffic is rerouted by this stage.
* With an independently issued server challenge and enrolled Guard machine
  credentials, run real HTTP allow/deny/forged-content/revocation challenges
  and submit matching Guard audit evidence to the control plane.
* With separate operator cutover approval, restart only the supported RAG
  service using the reviewed Gateway route, verify actual employee-facing
  allow/deny responses, and obtain a Guard-audited cutover receipt. If cutover
  verification fails, **stop the affected RAG service**, not silently bypass
  AccessProof or revert to an unprotected direct model route.
* After successful verified cutover, optionally request Protect preflight
  using separate ORG_ADMIN credentials. The control plane continues to require
  all source, identity, route and Guard acknowledgment checks. A missing
  approval, incomplete challenge or failed check leaves protection inactive.

## Preconditions

1. Explicit approval from the owner of the Docker host and its permitted RAG
   deployment. No SaaS remote-execution credentials are accepted.
2. Existing Docker Compose RAG must declare:
   `com.accessproof.gateway.contract=accessproof.gateway/v1`;
   `com.accessproof.gateway.enforces=attested-retrieval-and-buffered-output`;
   `com.accessproof.gateway.route_env=YOUR_MODEL_ENDPOINT_ENV`.
   These labels alone are **not sufficient proof**; signed source dependencies
   and actual output-path challenges remain required.
3. If the RAG uses a signed answer cache, declare
   `com.accessproof.cache.return_path=signed-manifest-guard-reauthorization/v1`
   after correctly integrating the AccessProof cache release contract. Redis,
   Memcached and PostgreSQL have local reference adapters; unmanaged cache
   returns, in-memory caches in other processes and arbitrary tool caches
   are **not** automatically intercepted.
4. Put RAG only on an internal network, model on a distinct internal network,
   Guard on a reachable approved internal network. Model must not be directly
   reachable from RAG. No privileged networking, Docker socket mounts or
   unreviewed external model destinations. Actual network-bypass certification
   is performed by the enrolled agent, not the preview report.
5. Register the source, Guard and AI application on the AccessProof web
   console. Validate live employee identities and source ACL freshness.
6. Hold customer-side signing keys, access tokens and identity probe data in
   private mode-0600 files on the customer host, never in the web form or CLI
   command line. The Guard machine credential differs from the ORG_ADMIN
   session credential.

## Installation spec (public settings only; must be private mode 0600)

```json
{
  "tenant_id": "REPLACE_CUSTOMER_TENANT_ID",
  "application_id": "REPLACE_REGISTERED_APP_ID",
  "rag_service": "rag",
  "guard_url": "http://guard:8080",
  "model_url": "http://model:8000/v1/chat/completions",
  "trusted_public_keys": {
    "customer-ingestion-key": "BASE64URL_32_BYTE_ED25519_PUBLIC_KEY"
  },
  "gateway_image": "accessproof-gateway:0.1.0",
  "listen_port": 8090
}
```

The actual public key must be created from the separate customer's trusted
source-ingestion key. Never use the example strings as working credentials.

## Supported guided commands

Run from the AccessProof repository on the approved customer Docker host;
adjust all file paths:

```bash
python -m apps.gateway.accessproof_gateway.integration_wizard plan \
  --spec ./accessproof-install-spec.json --compose ./compose.yml \
  --output ./.accessproof-gateway

python -m apps.gateway.accessproof_gateway.integration_wizard stage \
  --spec ./accessproof-install-spec.json --compose ./compose.yml \
  --output ./.accessproof-gateway

python -m apps.gateway.accessproof_gateway.integration_wizard install \
  --spec ./accessproof-install-spec.json --compose ./compose.yml \
  --output ./.accessproof-gateway --approve-gateway-install
```

After uploading the generated `installation.json` via **Applications →
Gateway setup**, obtain the enrolled Guard challenge and create private
`challenge.json` and `enrolled-guard.json` based on the control-plane
contract. Then:

```bash
python -m apps.gateway.accessproof_gateway.integration_wizard verify \
  --spec ./accessproof-install-spec.json --compose ./compose.yml \
  --output ./.accessproof-gateway \
  --challenge ./challenge.json --guard-credentials ./enrolled-guard.json \
  --receipt ./verify-result.json

python -m apps.gateway.accessproof_gateway.integration_wizard cutover \
  --spec ./accessproof-install-spec.json --compose ./compose.yml \
  --output ./.accessproof-gateway \
  --challenge ./challenge.json --guard-credentials ./enrolled-guard.json \
  --employee-route-probe ./employee-probe.json \
  --approve-route-cutover --receipt ./cutover-result.json
```

Alternatively, **once the installation is staged and a server-issued
challenge and route-probe configuration already exist**, the owner can perform
the approved install → enrolled challenge → verified cutover with ONE command:

```bash
python -m apps.gateway.accessproof_gateway.integration_wizard complete \
  --spec ./accessproof-install-spec.json --compose ./compose.yml \
  --output ./.accessproof-gateway \
  --challenge ./challenge.json --guard-credentials ./enrolled-guard.json \
  --employee-route-probe ./employee-probe.json \
  --approve-gateway-install --approve-route-cutover \
  --receipt ./approved-integration-result.json
```

**To request the existing Protect preflight after verified cutover:**
add `--approve-protect-request --admin-credentials ./org-admin-session.json`
to the `cutover` or `complete` command. Admin file (mode 0600) structure:

```json
{
  "control_plane_url": "https://api.accessproof.in",
  "admin_session_token": "REPLACE_WITH_A_REAL_ORG_ADMIN_SESSION_TOKEN"
}
```

The control plane may return `action_required` or `validating`; the wizard
returns `protect_active=false` until it confirms `protected`, an actual
Guard acknowledgment, and all server checks passing. Never edit that state
manually or skip its identity/ACL and route probes.

## Fail-closed behavior and limitations

* No remote one-click installation from the web control plane. The website
  cannot and should not silently access the customer's Docker socket.
* Existing RAG must honor the attested-provenance route and configured model
  endpoint. Discovery of labels/config does not prove how arbitrary code
  handles caches, tools, background jobs or network egress.
* Unsupported RAGs, custom framework versions, external hosted models,
  uncontrolled caches, shared model networks and missing encrypted customer
  signing material need a reviewed adapter and validation first.
* Without real Google Workspace/SharePoint employee ACL tests and source
  revocations, nobody can claim production permission timing or universal
  authorization coverage.
* The source project is never changed, and unverified installations never
  activate Protect. A failed post-cutover verification stops the selected RAG.
* `STAGED_UNVERIFIED`, `INSTALLED_UNVERIFIED`,
  `REFERENCE_TESTS_SUBMITTED` and `CUSTOMER_CUTOVER_VERIFIED` are distinct
  states. None automatically means `production_certification=true`.

## Evidence from local implementation tests

* Wizard plan, stage, installer approval, source-file fingerprint tampering,
  unsupported cache return paths, direct RAG-to-model network bypass,
  enrolled-challenge ordering, cutover approval and control-plane preflight:
  unit tests in `tests/unit/test_gateway_integration_wizard.py`.
* A real local `docker compose config` fixture was inspected and staged
  without changes to the source Compose file. The generated override
  connected the reviewed environment variable to the customer-side Gateway;
  no live service was started or modified.
* Web-v2 `/integrations/setup` passed ESLint, TypeScript type checking,
  and a Next.js production build.
* Full backend suite is rerun after code changes; the final result is
  recorded in the actual test log, not inferred from earlier tests.

**Commercial positioning:** "Guided one-command installation for supported,
attested-manifest Docker RAG deployments; independently verified Protect
activation" — **not** "instant one-click protection of arbitrary RAG apps".
