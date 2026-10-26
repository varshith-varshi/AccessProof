# AccessProof V2 Gateway readiness

## Executive verdict

**PARTIAL IMPLEMENTATION.** The repository has a locally tested strict Gateway reference boundary. It is not a one-click customer installation and is not production-ready for arbitrary RAGs.

## Architecture

`verified employee token -> Gateway -> Guard Layer 1 -> attested authorized source context -> configured model -> buffered answer -> Guard Layer 2 -> employee`.

## Confirmed findings and remediation

- **AP-GW-001 (high):** caller-controlled chat roles could add unverified context to privileged model messages. The generic message contract was removed. The Gateway now accepts only an employee question and employee-authored user turns; system/developer/tool/cache fields are rejected. Regression tests prove upstream receives no injected privileged context.
- **AP-GW-002 (high, incomplete operational chain):** a verifier existed without a production ingestion primitive. `TrustedSourceIngestor` now creates versioned signed chunks only from provider-authenticated, non-deleted source documents. Actual provider authentication remains an external deployment requirement.
- **AP-GW-003:** the Gateway can establish complete input lineage only for inputs it owns. It does so on its strict route; legacy SDK applications and opaque RAGs remain ineligible for certified Protect without their own trusted trace.

## Implemented capability

The Gateway verifies Ed25519 source bindings, performs both Guard layers, buffers output, rejects streaming and oversized requests, holds model credentials in server-side configuration, and does not forward employee tokens to the model. Docker packaging, UI catalog discovery, and runbooks are included.

## One-click integration

No one-click installer is claimed. The Docker package is repeatable but still needs authorized customer deployment configuration and a RAG that emits the attested manifest. Automatic install, challenge-agent evidence, and Protect activation remain incomplete.

## Evidence

Full backend regression passed after the latest changes: `559 passed, 1 xfailed`. Gateway/ingestion regression tests passed. TypeScript SDK passed: `34 passed`. web-v2 lint, typecheck, and production build passed. Gateway Docker image and both Compose configurations validated locally.

## External validation blockers

Authorized Google Workspace source ingestion, real OIDC/JWKS, customer model endpoint behavior, source-to-vector authenticity, Docker deployment-agent permissions, real revocation timing, and SharePoint effective-access certification remain required.

## Recommended next step

Build an authenticated customer-side deployment and challenge agent that can install the Gateway only into a reviewed Docker reference RAG and submit replay-resistant route evidence to the control plane.

---

## Local engineering follow-up (2026-10-23, after the original report)

**Verdict stays PARTIAL IMPLEMENTATION — NOT PRODUCTION READY.** Further
repository changes were completed in-place without touching production:

1. Fixed a UTF-8 source-ingestion bug affecting multibyte characters with a
   one-byte chunk budget (includes regression cases with mixed Unicode).
2. Bounded HTTP request bodies before full allocation and upstream model
   response bytes before JSON decoding.
3. Rejected unauthenticated Gateway requests before body schema validation.
4. Fixed a mixed authorized/denied retrieval bug: the Gateway's Layer 2 source
   trace now contains only the chunks actually supplied to the model, not
   denied retrieval candidates.
5. Added a customer-side Docker Compose installer that validates an explicit
   supported reference contract and stages an immutable, restricted override.
   The installer can build/start only Gateway after explicit `--apply`;
   it **does not silently reroute RAG traffic or activate Protect**.
6. Implemented a Google Drive trusted-ingestion adapter with authenticated
   provider fetch, root-boundary checks, before/after revision checks, bounded
   UTF-8 text download and Ed25519 source attestation.
7. Added an owner-run Google Drive ingest CLI with mode-0600 private signing
   key custody and exclusive output manifest creation.
8. Added local TCP end-to-end integration tests across real Guard, Gateway
   and mock model HTTP services, covering mixed retrieval, forgery,
   revocation during generation, post-generation denial and response bytes.
9. Extended focused Python tests and preserved Python/TypeScript SDK APIs.

**Independent test evidence:**
- Original full Python run after early fixes: **591 passed, 1 expected failure**
  (intentional known legacy SDK provenance limitation).
- End-to-end HTTP Gateway test passed following a real mixed-retrieval
  regression fix.
- Gateway + new installer + Drive ingestion tests passed.
- Docker Gateway image built and started in an isolated local smoke test.
- Liveness returned 200 and readiness correctly returned 503 while Guard was
  absent. The image needs a fresh rebuild after later authentication changes.
- A final full test-suite run is separately required after the last edits.

**Explicit unmet release gates:**
- No production customer-side installation and challenge/certification agent
  yet; local staging is not truly one-click protection.
- Control-plane automatic preflight still contains an intentionally
  unsatisfied `CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED` check.
- No trusted evidence that arbitrary third-party RAGs cannot bypass the
  installed Gateway via caches/tools/background routes.
- No real customer-side Google Workspace/Drive revocation and identity proof.
- No proven real customer vector-index update and OAuth refresh workflow for
  the new signed Google Drive CLI.
- Native provider adapters for Claude and Gemini, streaming, and generic
  no-code LangChain/LlamaIndex are not certified.
- Microsoft effective-permission certification remains a separate blocker.
- Real production Postgres, Redis, network-policy, identity, operational
  failover, customer approvals and safe deployment rehearsal are outstanding.

No live customer data, external production deployments or real provider
credentials were used. Do NOT override the Protect readiness gate.

## Final in-session verification addendum (2026-10-23)

- **Full Python suite:** 597 passed, 1 expected failure, 5 warnings
  (actual exit 0; `/tmp/accessproof_gateway_current_full_20261023.log`).
  The xfail remains the documented legacy metadata-only provenance limitation.
- **Additional local route challenge cases after full suite:** 6 passed.
- **Real TCP Gateway/Guard/model + route challenge:** passed, including
  synthetic mixed allow/deny retrieval, attestation tampering, and
  revocation during generation without releasing blocked model text.
- **TypeScript SDK tests:** 34 passed; TypeScript compilation passed.
- **web-v2 lint:** passed; **web-v2 TypeScript typecheck:** passed.
- **Ruff on new and touched Gateway/ingestion/tests:** passed;
  **git diff --check:** passed.
- **Docker Gateway:** rebuilt successfully after final authentication changes;
  isolated container returned HTTP **200** on liveness, HTTP **503** on
  readiness without a Guard, and HTTP **401** on an unauthenticated malformed
  chat request.
- **Docker Compose generated override:** validated against an actual local
  Compose fixture, with the private environment file at mode **0600**.
- **Local challenge observer:** supports controlled allow, deny, forged
  content and Layer 2 revocation probes via real HTTP, but deliberately
  emits `production_certification=false` and **cannot activate Protect**.

**FINAL RELEASE VERDICT: PARTIAL / LOCAL REFERENCE IMPLEMENTATION READY;
NOT PRODUCTION READY.** The remaining blockers are not resolved by local
unit tests: an authenticated automated customer installer that actually
verifies and secures the full RAG route, machine-attested challenge/control-
plane activation, real provider permission/revocation validation, original
RAG bypass proof, production-like resilience testing and approved deployment.

**Production rollout and real customer credentials were intentionally not
used.** Existing Python and TypeScript SDKs were retained.

### Additional customer-side diagnostics and packaging work

- Added a local HTTP byte-observing challenge agent and mode-0600 diagnostic
  CLI. It checks allow, denial, forged-content, and in-flight revocation
  responses against exact failure codes; generic Guard 503 errors do not pass.
- The diagnostic explicitly returns `production_certification: false`.
  **Do not use it to bypass the missing control-plane challenge certificate.**
- Added independent reference TCP tests confirming the challenge agent reads
  real Guard/Gateway/model service responses rather than relying solely on
  internal SDK method results.
- Hardened the shipped Gateway Compose package: pinned image tag default,
  non-root process, read-only filesystem, dropped Linux capabilities,
  no-new-privileges, bounded memory/processes, and a readiness healthcheck
  that fails if Guard is not healthy.
- Added a Gateway-level check rejecting any Shadow `would_allow` SDK result
  on its Protect-only route (with explicit regression test).
- The complete backend suite had **597 passed, 1 expected failure** before
  the latest minor challenge/packaging changes. Focused regressions are run
  separately against subsequent code edits; a new full run is required to
  claim the final snapshot as fully green.

### Verified local Docker installer smoke — 2026-10-23

The first disposable installer application revealed an HTTP startup race:
`docker compose up -d` exited successfully before Uvicorn accepted
connections, resulting in an immediate connection-reset during the smoke
probe. The installer was corrected to wait for actual Gateway HTTP
liveness before reporting `INSTALLED_UNVERIFIED`. It refuses to restart a
pre-existing Gateway and attempts a **Gateway-only rollback** after a newly
started installation fails, without changing the customer's RAG service.

A second disposable Docker project then verified:

- `installer --apply` exited successfully.
- Gateway local liveness returned HTTP **200**.
- Gateway readiness without an enrolled Guard returned HTTP **503**.
- Original customer Compose file was unchanged.
- No customer RAG traffic was automatically redirected.
- The generated confidential environment file had private 0600 permissions.
- Scratch Gateway containers were removed after the test.

This demonstrates local container deployment mechanics only; it does not
establish one-click *protection* or full production readiness.

### Unresolved provenance boundary that cannot be solved by a proxy alone

The certified Gateway still accepts a caller-supplied `employee_question`
and employee-authored conversation text. In a normal application this may be
legitimate user input, but the Gateway cannot **independently prove** that the
customer RAG has not moved enterprise retrieval or cache content into those
fields. The context-injection fix rejects privileged message roles and
unstructured document-bearing fields, but it does not establish
cryptographic *employee-question provenance* for arbitrary customer RAG
code. Certified no-code deployments need a trusted employee-ingress
boundary or an equivalent independently verifiable origin contract.

Do not claim that every document-bearing model input is covered until this
origin boundary, additional retrieval/cache/tool routes and alternate model
egress are comprehensively verified.

### Final independent validation

The final Python regression suite was rerun after local installer, challenge,
ingestion and Gateway hardening. Exact final totals are recorded in the
local test command output (and must be updated after completion).

## Final verified local test summary — October 23, 2026

- **Python complete supported test directory:** 610 passed, 1 strict expected
  failure, 5 warnings (exit 0; ~6m16s). The expected failure is the existing
  metadata-only legacy SDK provenance gap; it was not silently removed.
- **New Gateway, installer, Google Drive ingress, local challenge and real
  TCP integration focused tests:** 59 passed, 3 warnings (exit 0).
- **TypeScript SDK:** 34 passed, no failures; TypeScript compilation passed.
- **Web console:** ESLint passed, TypeScript typecheck passed, and Next.js
  production build passed (exit 0).
- **Gateway Docker:** local image built; customer-side installer applied to a
  disposable Docker project, waited for liveness HTTP 200, and correctly
  reported Guard readiness HTTP 503 with no enrolled Guard. Scratch containers
  were removed after tests. Original customer Compose source was unchanged.
- **Static verification:** Ruff passed for changed Gateway/ingestion/installer
  modules; Docker Compose configuration validated; git diff whitespace checks
  passed. No production deployment or real customer OAuth was attempted.

**Authoritative release decision: LOCAL REFERENCE INTEGRATION READY only.**
The feature is not yet production ready or independently certified as
one-click Protect for arbitrary RAG applications. The intentionally unsatisfied
`CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED` control remains in place. Customer
installation/cutover requires a separately authorized integration, a trusted
employee-input and retrieval boundary, real provider identity and revocation
validation, route/egress bypass testing, operator acceptance, Guard-enrolled
challenge acknowledgments, and production availability/security review.

The existing Python/TypeScript SDK integration choices are preserved. Do not
misrepresent experimental customer-side installer and diagnostic support as a
universal zero-code RAG integration.

## Additional controlled reference cutover work — October 23, 2026

- Added customer-side CLI `customer_agent` with real HTTP security probes,
  checked against an isolated, signed-source Docker reference network.
- Added a separately approved `customer_cutover` command: it explicitly
  applies the reviewed RAG service override, probes the **actual employee
  application** with allowed/denied synthetic employees, verifies returned
  Guard decision IDs, and sends bounded metadata to the enrolled control plane.
- Added required negative and tampered employee-facing route proofs. Customer routing
  does **not** pass after a positive test alone; the backend also requires
  matching Guard Layer 1 deny audits for a second request ID.
- On post-cutover verification failure, the customer-side CLI attempts to stop
  **only** the changed RAG service rather than falling back to an unprotected
  model. Customer operations approval and outage planning remain mandatory.
- Added `--apply-staged`: previously reviewed local installer files can be
  checked for tampering and applied without overwriting a private output dir.
- Gateway network assignment now uses explicit RAG/model isolation whenever
  the initial Compose topology supports it.
- Validated an isolated disposable Docker Compose merge. The resulting
  Gateway joined both networks, the RAG route pointed to Gateway, and the
  route verifier accepted the isolated stack, explicitly **not** granting
  production certification.
- Added adversarial tests for Gateway-only and unpublished endpoint spoofing,
  source-content canary leakage, Shadow output, direct-model routing,
  invalid post-cutover denial, changed installer manifests, replay and
  unapproved installation.
- Explicitly **not performed:** production deployment, real customer
  Google Workspace permissions/revocation, autonomous customer service
  cutover, a production provider identity proof, a multi-machine failover,
  arbitrary RAG path certification, or managed cloud egress enforcement.

Release verdict remains **controlled reference workflow, not a general
production-ready one-click integration** until those environment-dependent
gates are satisfied and the final regression run passes.

---

## 2026-10-23 — Supported reference automatic challenge / cutover implementation

This section **supersedes earlier claims** that the challenge machinery
is completely absent. The earlier sections reflect the previous baseline.

### New production-control-plane components

- An operator may issue a one-time, ten-minute reference challenge, bound to
  the exact tenant, Guard, source, app, adapter, installed policy version,
  customer Compose deployment digest and loopback Gateway URL digest.
- A new `rag_route_challenges` table, Alembic migration
  `d5e7f9a1b3c5`, and PostgreSQL forced tenant RLS persist the challenge.
- Only the exact enrolled Guard machine credential may submit reference
  Gateway HTTP results, which must match four authenticated Guard Layer 1/2
  audit sequences. All request IDs derive from a server-issued nonce.
- A **separate post-cutover Guard corroboration** confirms fresh
  employee-facing positive, denied, and forged-attestation request outcomes.
  A generic Guard outage or unverified 503 cannot satisfy negative evidence.
- Customer source and directory sync, Guard policy status, OIDC/identity and
  enrolled Guard acknowledgment remain mandatory activation prerequisites.
- The activation route can now transition `shadow → protect_pending →
  protect` for a deliberately supported reference deployment after every
  check passes. It does not enable arbitrary SDK or proprietary RAG routes.
- Installer reports a mode-0600 deployment hash manifest and the console
  provides a guided setup / manifest upload / challenge / status panel.
- A customer-side isolated Docker network checker, machine challenge agent
  and separately approved RAG Compose cutover CLI automate supported
  reference testing and a limited cutover with rollback attempts.

### Security scope and release decision

**Local reference integration: IMPLEMENTED AND SYNTHETIC-TESTED.**
**Universal one-click customer RAG: NOT IMPLEMENTED.**
**Production Protect for real customer environments: NOT VALIDATED.**

Actual Google Workspace permission freshness, employee OIDC mapping,
customer egress enforcement, continuously signed indexing/revocation,
network rollback, active model/Guard topology, and real customer application
authorization must be established separately.

Do not deploy production components or apply migrations on an existing
production DB without explicit authorized change-control approval.

### Post-cutover fail-closed hardening

The customer-side reference cutover no longer restores a potentially
unprotected application route when its authorization checks fail. The
selected customer RAG service is stopped pending explicit operator review.
No production or real customer RAG was stopped; only local mock tests were
used for this failure path.

### Final reference model scope clarification (Oct 23)

For the certified **reference** Compose path, the Guard, RAG and model must
be reachable over declared customer-controlled Docker networks. The RAG may
not share the isolated model network; Gateway joins all three networks. A
real customer chat endpoint is tested with three independent synthetic
requests after explicit operator routing approval (allow, deny, forged
attestation), and the control plane matches those request IDs to Guard
Layer 1/Layer 2 audit events. On failure, the customer-side route CLI attempts
to stop only its RAG service. This is not an automatic internet-scale
agent installation and it does not prove unrelated route/code/host security.

The final snapshot regression run is recorded separately after completion.

---

## End-of-session verified release checkpoint — 2026-10-23

**Scope:** Customer-side automated Gateway integration for an explicitly
supported, isolated Docker reference RAG using a pinned, in-stack model and
a trusted signed document-ingestion path.

### Executed and verified

- **Final complete Python `tests/` suite: 661 passed, 1 expected failure,
  5 warnings** (exit 0; approximately 6m18s). The strict expected failure
  documents the unchanged legacy metadata-only SDK provenance vulnerability
  and is excluded from the new certified signed-content Gateway contract.
- Most recent targeted Gateway/Guard/reference/cutover/security tests:
  **106 passed**. The later bounded machine-audit polling change also
  passed its additional targeted regressions (**4 passed**).
- TypeScript SDK: **34 passed**, TypeScript compilation passed; existing SDK
  integration choices remain available.
- Web console: ESLint, TypeScript compilation and Next.js production build
  passed.
- New `rag_route_challenges` Alembic migration applied to disposable SQLite
  and disposable PostgreSQL databases. On PostgreSQL,
  `relrowsecurity=true`, `relforcerowsecurity=true`, and the tenant
  policy was present. No production database changes were made.
- A disposable Docker networking test verified that the synthetic RAG could
  connect to Gateway and was denied direct model access, while Gateway could
  reach the local model. All scratch containers/networks were cleaned up.
- The customer-side Docker Gateway installer built and launched in a
  disposable Compose project, reported liveness HTTP 200 and readiness HTTP
  503 when Guard was not configured. The original customer Compose file
  was unchanged.

### Implemented

- Machine-authenticated route challenge issuance/submission, nonce expiration,
  replay prevention, tenancy and application/Guard/source/deployment binding.
- Cross-check of allow/deny/tamper/in-flight-revocation HTTP observations
  against fresh enrolled Guard audit decisions.
- A separate employee-facing post-cutover evaluation including authorized,
  denied and forged-source outcomes, each independently linked to Guard events.
- Fail-closed Protect activation with Guard heartbeat acknowledgment only
  after every required readiness check passes.
- A guided dashboard panel for approved deployment manifest selection,
  challenge issuance and verification-status review.
- A customer-side reference isolation checker and authenticated challenge
  agent; delayed Guard audit uploads now receive bounded, security-specific
  retry instead of manual intervention.
- Explicitly approved local RAG cutover with fail-closed service shutdown
  on failed enforcement tests, never a silent restore to a direct-model route.

### Unresolved release gates — production status: NOT VALIDATED

- No real external customer RAG's complete ingress/retrieval/cache/tool/model
  paths have been independently certified against bypass.
- No real Google Workspace permission and revocation lifecycle with
  trustworthy employee OIDC identities, root boundary and group membership
  was tested in this session.
- Signed Google Drive ingestion remains a limited text-file utility; it
  does not automate real-time document indexing, provider refresh, or all
  supported enterprise file types.
- The isolated Docker reference requires customer-provided compatible
  application routing and deployment topology. Arbitrary RAG and external
  LLM APIs are not a one-click integration.
- No authorized live deployment, production data migration, end-user
  rollback/availability rehearsal, or third-party security attestation was
  attempted.

**Current release label: LOCAL REFERENCE GATEWAY + SYNTHETIC AUTOMATIC
PROTECT ACTIVATION PATH IMPLEMENTED; CONTROLLED CUSTOMER PILOT NEEDS
REAL PROVIDER/NETWORK EVIDENCE.**

No customer infrastructure or production secrets were touched.

### Resolved scratch-host Docker networking defect; final checks (Oct 23)

A real scratch deployment exposed that a Gateway attached **only** to
`internal: true` Docker networks could not be reached through its
`127.0.0.1:published-port` mapping. A standalone disposable HTTP-server test
returned HTTP **000** in that topology, then HTTP **200** after a normal
bridge network was added. The installer now attaches **only the Gateway** to
`accessproof-gateway-host` (non-internal), in addition to the isolated RAG,
model and Guard networks. The customer RAG stays exclusively on its isolated
network; model and Guard do not join the Gateway host-access network.
Certification rejects an incorrect/shared host bridge.

Verified disposable `--apply-staged` result after the fix:

- Staging exit **0**, reviewed installation apply exit **0**.
- Live Gateway HTTP **200**.
- Gateway readiness HTTP **503** without an enrolled/healthy Guard, as
  required for safe denial of unverified protection.
- Gateway networks: `accessproof-gateway-host`, `guard-private`,
  `model-private`, `rag-isolated`.
- Customer RAG networks: `rag-isolated` **only**.
- No customer RAG traffic rerouted, no production service modified.
- All disposable test containers and uniquely named scratch networks removed.

Verification evidence:
- Full Python test suite **661 passed, 1 expected failure (xfail), 5 warnings,
  exit code 0** before the final isolated-host networking patch.
- **52 focused installer/network/customer-agent/cutover tests passed**
  after the isolated-host networking patch.
- The extra post-cutover forged-content + machine-Guard/API focused regression
  also passed (19 tests).
- Web lint, TypeScript typecheck and Next.js production build passed.
- Disposable Alembic migration to new `rag_route_challenges` table succeeded.
- No customer credentials, production access, or live provider APIs used.

**Final release decision:** A robust, automated, *operator-approved reference
Docker Gateway workflow* is implemented and locally validated. It is not a
production certificate for an arbitrary customer RAG or all LLMs. Real
customer provider permissions/revocation, verified OIDC identities, complete
cache/tool/background-route bypass testing, an owner-approved deployment and
observability/recovery remain mandatory for a controlled external pilot.
