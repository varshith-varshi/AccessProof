# AccessProof — Canonical Engineering Context

> Snapshot date: 2026-10-17
> Local repository inspected directly with Desktop Commander.
> This file is a continuity aid for future ChatGPT/engineering sessions. **The live source code, Git state, database migrations, and deployed configuration always override this document if they disagree.** Re-inspect before changing anything.

## 0. Future-session startup protocol

When opening a new ChatGPT session, tell the assistant to use Desktop Commander and read this file first. Then it should:

1. `cd /home/white-devil/Downloads/accessproof/f15`
2. Run `git status --short`, `git branch --show-current`, and `git rev-parse HEAD`.
3. Inspect current diffs before editing. Never overwrite unknown/uncommitted work.
4. Read the relevant current source files instead of assuming this snapshot is still exact.
5. Use the repository's real test/build commands and verify claims with execution.
6. Treat production as read-only unless the user explicitly approves a deployment/change.
7. Never print secrets, tokens, passwords, private keys, OAuth credentials, SMTP credentials, database passwords, or `.env` contents.
8. Prefer: inspect → reproduce → root-cause → smallest correct fix → targeted test → related tests → full regression.

## 1. Product definition

**AccessProof is a real-time authorization enforcement layer for enterprise AI/RAG systems.**

Core positioning:

> AccessProof makes enterprise AI respect enterprise authorization.

Current web-v2 positioning in source is aligned with:

> Make enterprise AI respect existing permissions in real time.

The core security questions are:

1. Can an AI system reveal sensitive information to an employee who was never authorized to access the underlying enterprise resource?
2. Can the AI continue revealing information after that employee's access has been revoked?

Critical principle:

> We do not authorize questions. We authorize the enterprise resources used to answer them.

Working motto:

**Sync → Resolve → Enforce → Verify → Audit**

## 2. Core architecture and invariants

```text
Enterprise permission source/change
        ↓
Permission synchronization / event
        ↓
Effective-access resolution
        ↓
Versioned policy
        ↓
Customer-side AccessProof Guard
        ↓
Layer 1 — pre-generation resource authorization
        ↓
Authorized RAG context only
        ↓
LLM
        ↓
Layer 2 — trusted provenance verification
        ↓
Safe response
        ↓
Audit / protection evidence
```

### Authorization semantics

- Decisions are **ALLOW / DENY / UNKNOWN**.
- `UNKNOWN` must never silently become `ALLOW` unless the application is explicitly configured for fail-open behavior.
- Effective access must consider **all** applicable grants. Removing one grant must not produce DENY if another valid grant still authorizes access.
- Stale events/revisions must never overwrite newer authorization state.
- Cross-tenant state changes or reads are release-blocking defects.
- Authorization must be based on stable enterprise resource identifiers and trusted subject identity, not prompt wording.

### Shadow and Protect

- **SHADOW** evaluates what would happen and records outcomes such as WOULD_ALLOW / WOULD_BLOCK / UNKNOWN / ERROR without changing the RAG response path.
- **PROTECT** actively enforces authorization.
- Layer 1 removes denied resources/chunks before the LLM sees them.
- Layer 2 checks trusted provenance before the response is released and can block/regenerate unsafe output.
- Protect should buffer generated output until the Layer 2 verdict; do not stream unsafe tokens to the employee first.
- New integrations should normally begin in Shadow and move to Protect only after readiness is verified and authorized.

### Trusted provenance

Layer 2 must **not** trust an LLM's self-reported statement about which documents it used. Trusted provenance comes from system-controlled metadata such as:

- retriever output metadata
- vector/database metadata
- chunk → resource mappings
- tool-call outputs
- orchestration traces

Derived objects should preserve lineage where the integration provides it (for example summaries, chunks, caches, AI memory, tool-returned context). If denied input materially contributed and the contribution cannot be separated, the safe behavior is block or regenerate using only authorized sources.

### Identity

Never trust arbitrary browser/request JSON such as an email or `user_id` as proof of employee identity. Identity should come from validated mechanisms such as OIDC/JWT, signed assertions, mTLS, or other trusted gateway identity. Validate relevant signature/algorithm/issuer/audience/expiry/not-before/tenant/subject constraints.

### Guard availability

The customer-side component is called **AccessProof Guard**. Do not use the old term “Private Runner” as the customer-facing name.

The Guard should enforce the last valid durable installed policy through temporary control-plane outages. It must not recover into an empty allow-all state. Policy installs need revision/version protection and tenant binding.

## 3. Real repository snapshot

Local repository root:

```text
/home/white-devil/Downloads/accessproof/f15
```

At this snapshot:

```text
Branch: master
HEAD: ab59ffd77106c71ced7e9876c45a486386556746
Commit: ab59ffd Harden Guard concurrency and durable recovery
```

Toolchain observed on the development machine:

```text
Python 3.10.12
Node v20.19.5
npm 10.8.2
Docker 29.9.0
Docker Compose v5.6.0
Alembic head: 0004_microsoft_connectors
```

### Important current uncommitted work

At the time this context file was created, `git status --short` showed these pre-existing modifications:

```text
M apps/api/accessproof_api/app.py
M docker-compose.ec2.yml
M web-v2/app/api/[...path]/route.ts
?? web-v2.zip
```

The three modified files and the pre-existing `web-v2.zip` artifact were **not** created by writing this context file and must not be overwritten/reverted/deleted casually. `ACCESSPROOF_CONTEXT.md` itself is newly created by this documentation task.

Observed purpose of those diffs:

- `apps/api/accessproof_api/app.py`: request/proxy-aware secure-cookie handling for login/session behavior.
- `docker-compose.ec2.yml`: production web service changed to the versioned web-v2 image and Next.js health check/config.
- `web-v2/app/api/[...path]/route.ts`: server-side API proxy cookie handling based on forwarded protocol.

Always re-run `git diff` because this snapshot can become stale.

## 4. Repository structure

Major current directories/files inspected:

```text
apps/api/accessproof_api/       FastAPI control-plane/API
apps/guard/accessproof_guard/   Guard HTTP application
apps/worker/                    asynchronous/background worker
packages/auth/                  authentication helpers
packages/config/                shared configuration
packages/domain/                domain models/scenarios
packages/guard/                 Guard engine/cache/identity/provenance/storage
packages/protection_evidence/   protection/audit evidence support
connectors/google_drive/        Google Drive connector/client
connectors/microsoft/           Microsoft connector/client
connectors/scanner/             scanner connector
reference_rag/                  reference RAG/integration code
web-v2/                         CURRENT production frontend
web/                            legacy frontend; do not confuse with web-v2
deploy/                         Nginx/deployment configuration
migrations/                     Alembic migrations
tests/                          unit/integration/security test suites
.github/                        CI/workflow configuration
docker-compose.yml              local/default Compose
docker-compose.ec2.yml          EC2 production Compose
docker-compose.production.yml   additional production-oriented Compose
```

Historical root documents such as `README.md`, `FINAL_ARCHITECTURE.md`, `FINAL_VALIDATION_REPORT.md`, `IMPLEMENTATION_STATUS.md`, and `UPGRADE_AUDIT.md` are useful history but may describe earlier product stages. **Current source, recent commits, tests, and live configuration take precedence.**

## 5. Backend / control plane

Key API files currently present:

```text
apps/api/accessproof_api/app.py
apps/api/accessproof_api/auth.py
apps/api/accessproof_api/config.py
apps/api/accessproof_api/connectors.py
apps/api/accessproof_api/db.py
apps/api/accessproof_api/guard_distribution.py
apps/api/accessproof_api/guard_pipeline.py
apps/api/accessproof_api/mail.py
apps/api/accessproof_api/middleware.py
apps/api/accessproof_api/models.py
apps/api/accessproof_api/policy.py
apps/api/accessproof_api/protections.py
apps/api/accessproof_api/schemas.py
apps/api/accessproof_api/scim.py
apps/api/accessproof_api/source_sync.py
apps/api/accessproof_api/integrations/
apps/api/accessproof_api/workers/
```

The API currently contains functionality for health/configuration, browser authentication/session management, signup/email verification/password reset, MFA, API keys, OIDC, SCIM, authorization decisions, events/revocations/grants, service accounts, connectors, RAG targets, runs, permission sources/sync, Google and Microsoft source authorization flows, AI applications, Guard enrollment/tokens/policies/health, Shadow/Protect surfaces, blocked requests, audit/policy snapshots, billing/admin areas, protection/testing hooks, integrations, and notifications.

Do not expose Guard machine credentials or machine-only Guard APIs through the browser as ordinary user APIs.

## 6. AccessProof Guard

Guard application:

```text
apps/guard/accessproof_guard/app.py
```

Core Guard implementation:

```text
packages/guard/agent.py
packages/guard/cache.py
packages/guard/identity.py
packages/guard/models.py
packages/guard/provenance.py
packages/guard/service.py
packages/guard/storage.py
packages/guard/transport.py
```

Current Guard HTTP routes found in source:

```text
GET  /healthz
GET  /readyz
GET  /version
POST /api/v1/decide
POST /api/v1/guard/filter-context
POST /api/v1/guard/check-output
POST /api/v1/guard/sync
```

Guard properties that are release-critical:

- durable local policy cache (SQLite-backed in the current architecture)
- reject stale/wrong-tenant/malformed policy installs
- Layer 1 pre-generation resource filtering
- Layer 2 trusted-provenance verification
- validated machine/user identity
- safe restart and control-plane-outage behavior
- auditable decisions with policy/version context
- no empty allow-all fallback

## 7. Source connectors and RAG integration

Current source code includes:

```text
connectors/google_drive/client.py
connectors/google_drive/connector.py
connectors/microsoft/client.py
connectors/microsoft/connector.py
connectors/scanner/
```

The repository also contains real-client/invalidation/token-renewal tests and real-target / Google Drive RAG proof paths. Presence of code/tests is **not** the same as current real-enterprise validation. Re-check credentials/environment and test evidence before claiming a provider is production-validated.

Full Protect integration requires, at minimum:

1. trusted employee identity
2. stable resource IDs
3. a hook after retrieval and before LLM generation
4. trusted provenance before response delivery

Black-box prompt→answer systems without these hooks cannot provide full Protect guarantees; classify them honestly as limited/Shadow-only where appropriate.

## 8. Current frontend: web-v2

**`web-v2/` is the current production frontend. `web/` is legacy.**

Current web-v2 stack from `web-v2/package.json`:

```text
Next.js 16.0.1
React 19.2.0
TypeScript 5.x
Playwright 1.56.x
ESLint 9.x
```

Canonical scripts:

```text
npm run dev
npm run lint
npm run typecheck
npm run build
npm run test:e2e
```

Current major route areas include:

```text
public landing
login / register / verify-email / resend-verification
forgot-password / reset-password
dashboard
employees
permissions/sources
permissions/events
ai-apps
guards
protection
blocked-requests
audit
reports
settings
diagnostics
admin/compliance and pilot-related pages where present
```

Public contact mailbox in the current landing experience is `admin@accessproof.in`. Do not invent aliases such as `pilot@accessproof.in` unless a real mailbox is configured.

## 9. Database and state

Primary control-plane database: **PostgreSQL 17**.

Local Compose currently uses a PostgreSQL service named `db` and Redis 7 Alpine. Local databases observed in the running development database container were:

```text
accessproof
accessproof_current
postgres
```

The active development API path uses `accessproof_current` in the inspected local Compose setup. Dev-only Compose credentials/defaults are not production credentials and must never be copied into production.

Current public-schema tables observed in `accessproof_current`:

```text
account_mfa
active_rag_runs
ai_applications
alembic_version
api_keys
billing_subscriptions
blocked_requests
connectors
datasets
effective_access
events
groups
guard_enrollment_tokens
guard_instances
guard_policy_acks
guard_tokens
identity_group_memberships
oidc_states
organizations
permission_sources
policy_snapshots
profiles
protection_events
protections
rag_targets
refresh_tokens
reports
revocations
scenario_runs
service_accounts
shadow_decisions
system_settings
update_runs
user_access_grants
users
webhook_integrations
webhook_subscriptions
workspaces
```

Additional model classes exist for decisions, connector secrets, audit events, source sync requests, OAuth state, permission groups, etc.; inspect current `apps/api/accessproof_api/db.py` and migrations for authoritative schema.

Redis is used for queue/worker/runtime coordination, but critical authorization/revocation correctness must be recoverable from durable PostgreSQL state where designed.

Guard durable state uses SQLite in the customer-side Guard architecture; local Compose mounts Guard state under `/var/lib/accessproof-guard`, with policy DB path `/var/lib/accessproof-guard/policy.db` in the inspected configuration.

## 10. Local Docker/Compose

Default local Compose file:

```text
/home/white-devil/Downloads/accessproof/f15/docker-compose.yml
```

Typical local host bindings observed:

```text
API        127.0.0.1:8000
web        127.0.0.1:3000
Guard      127.0.0.1:8080 (profile-dependent)
PostgreSQL 127.0.0.1:5432
Redis      127.0.0.1:6379
```

Important: the default local `web` service is historically tied to the legacy `./web` frontend. Do not infer production frontend state from the local `web` container. Test `web-v2` explicitly when validating the current UI.

## 11. Production EC2 snapshot

Production project root:

```text
/home/ubuntu/accessproof
```

Production Compose file:

```text
/home/ubuntu/accessproof/docker-compose.ec2.yml
```

**On EC2, use the explicit production file:**

```bash
docker compose -f docker-compose.ec2.yml ps
docker compose -f docker-compose.ec2.yml config --services
```

Do not rely on plain `docker compose ...` on the server: during the 2026-10-17 investigation, the default Compose resolution exposed only `db` and `redis`, while the running production stack had been created from `docker-compose.ec2.yml`.

Production services verified from the explicit EC2 Compose file:

```text
db
redis
api
web
nginx
worker
```

Production URL:

```text
https://app.accessproof.in
```

Production frontend verified on 2026-10-17:

```text
container: accessproof-web-1
image:     accessproof/web-v2:ab59ffd
restart:   unless-stopped
state:     running / healthy
internal:  3000/tcp
```

Production Nginx verified on 2026-10-17:

```text
container: accessproof-nginx-1
image:     nginx:1.27-alpine
restart:   unless-stopped
state:     running
public:    80/tcp and 443/tcp
```

Current production routing verified from Nginx configuration:

```text
app.accessproof.in
        ↓
Nginx
        ↓
web:3000
        ↓
web-v2
```

API traffic is proxied to `api:8000` where configured. HTTP redirects to HTTPS. Current HTTPS config includes HSTS, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy headers.

Production PostgreSQL and Redis are internal Compose services; they are not published as public host ports in the inspected EC2 configuration. Nginx is the public application ingress.

Current production storage configuration uses named volumes for PostgreSQL and Redis. Never delete/prune production volumes as a routine troubleshooting step.

A live check through Desktop Commander on 2026-10-17 returned HTTP/2 200 from `https://app.accessproof.in` with Nginx and Next.js headers. A 200 alone is not enough for a release check: verify a unique web-v2 page/content marker if frontend identity matters.

### Web-v2 cutover lesson

An SSH/laptop disconnect does **not** make the website revert. The earlier legacy-UI behavior was a deployment persistence/cutover issue. The persistent production path must remain:

```text
app.accessproof.in → Nginx → one frontend service → web-v2
```

Do not reactivate the legacy frontend through Compose, Nginx, startup scripts, restart policies, old images, or service-worker/cache behavior.

## 12. Test inventory

The repository has substantial unit, integration, security, concurrency, recovery, and browser coverage. Important current test areas include:

- permission events / permission sync / source sync
- authentication and browser-session security
- tenant isolation and IDOR controls
- Guard policy cache/install/sync/ack/revocation/runtime
- Guard Layer 2 provenance and Protect readiness
- policy generation/revision/versioning
- Google Drive invalidation and real API client
- Microsoft invalidation and real API client
- token renewal
- real target / real Google Drive RAG proof paths
- PostgreSQL concurrency
- Redis/worker recovery durability
- report authenticity
- request limits / secrets / cache / PII / connector hardening
- Golden authorization scenarios
- web-v2 Playwright E2E

Representative Golden scenarios historically verified:

1. Never Authorized
2. Revoked Access
3. Overlapping Grants
4. Derived Provenance
5. Guard Restart
6. Control-Plane Outage

### Last known verified engineering baseline (historical; re-run before claiming current green)

Prior engineering sessions recorded the following successful baseline before this context file was created:

```text
Backend full suite: 205/205 passed in two full runs
Golden E2E: 6/6 passed
Frontend: ESLint PASS, TypeScript PASS, production build PASS
Playwright: 15 passed, 1 skipped
PostgreSQL concurrency: 20 stress iterations, 0 deadlocks/failures
Redis durable recovery matrix: PASS
```

This is a **historical baseline**, not permission to skip tests. Any source change after that baseline can invalidate it. The final regression must run after the last code change.

## 13. Product boundaries / integration model

AccessProof is not intended to replace the customer's RAG, LLM, vector database, or enterprise permission source. It wraps/enforces authorization around the existing AI pipeline.

Typical protected flow:

```text
Employee prompt
→ customer retriever
→ candidate chunks/resources with trusted IDs
→ AccessProof Guard Layer 1
→ denied resources removed
→ customer's LLM receives authorized context only
→ generated output buffered
→ trusted retrieval/tool provenance passed to Guard Layer 2
→ allow / block / regenerate
→ safe response delivered
→ audit evidence recorded
```

The customer's existing OpenAI/Azure OpenAI/Claude/Gemini/Llama/etc. model can remain in place. Full Protect depends on the integration exposing trusted identity, stable resource identifiers, a pre-generation authorization hook, and trusted provenance.

Primary customer fit: internal enterprise AI/RAG or enterprise search over permissioned data where different employees/groups have different access and those permissions can change over time.

A public chatbot over fully public documents does not necessarily need per-user AccessProof authorization.

## 14. Cloud vs customer-side architecture

Control plane/cloud responsibilities include web/API, PostgreSQL, Redis/workers, source/policy administration, audit/reporting, Guard enrollment/distribution/health, and operational UI.

Customer-side Guard responsibilities include trusted identity validation, durable policy state, Layer 1, Layer 2, local enforcement, integration with customer RAG/source context, and local/forwarded audit behavior.

The Guard should prefer outbound control-plane communication and should not require a synchronous cloud round-trip for every protected AI request when the cached policy is valid.

## 15. Security rules for engineering work

Treat the following as non-negotiable unless the architecture is deliberately redesigned and fully reviewed:

- Never weaken authentication/authorization just to make tests pass.
- Never disable tenant isolation to simplify queries.
- Never change UNKNOWN to implicit ALLOW without explicit fail-open policy.
- Never trust prompt semantics as authorization evidence.
- Never trust arbitrary client-provided identity fields without cryptographic/gateway validation.
- Never trust LLM self-reported citations as sole provenance.
- Never expose Guard machine credentials in browser code.
- Never store secrets in Git or bake them into frontend bundles/images.
- Never use wildcard CORS in production unless there is a narrowly justified architecture reason.
- Browser session cookies should preserve the intended HttpOnly/Secure/SameSite security properties for the deployment path.
- Do not log raw JWTs, OAuth tokens, API keys, passwords, reset tokens, verification tokens, private keys, or source credentials.
- Avoid destructive production database/volume commands.

When testing tenant isolation, use at least two tenants and verify that object-ID manipulation cannot access the other tenant's users, resources, policies, Guards, sources, audit, reports, AI apps, or secrets.

## 16. Timing semantics

Do not collapse authorization propagation into one misleading timestamp. Where the system exposes these concepts, preserve the distinction between:

```text
event_observed_at
event_received_at
effective_access_resolved_at
policy_committed_at
guard_received_at
guard_installed_at
protection_verified_at
```

Do not claim “zero exposure” when source observation/detection latency is unknown. Mutation acknowledgement, effective source-side denial, policy commit, Guard install, and end-to-end protection verification are different events.

## 17. Provider/external-validation boundary

Code presence and mock/integration tests do not prove a real customer/provider deployment. Before making external claims, explicitly determine whether each item is:

```text
IMPLEMENTED
LOCALLY VERIFIED
REAL PROVIDER VERIFIED
CUSTOMER/PILOT VERIFIED
```

Historically, real Microsoft/Entra/Graph/SharePoint tenant validation remained a key external-validation boundary even though Microsoft connector code and tests exist. Google Drive has deeper real-client/RAG proof code, but current real-account/OAuth state must still be rechecked before claiming production verification.

Also verify real customer RAG integration, real OAuth token expiry/refresh/revocation behavior, and enterprise-network Guard deployment separately from local tests.

## 18. Authentication / account surfaces

Current API/source contains account capabilities for email/password authentication, signup/invitation, email verification/resend, forgot/reset password, browser sessions, MFA, API keys, OIDC, and SCIM-related enterprise identity management.

Operational/security intent:

- public unauthenticated pages are limited to auth/onboarding flows and intentionally public product pages
- product pages require an authenticated session
- session fixation/logout/expiry behavior must be tested
- verification/reset tokens should be random, expiring, single-use, and protected from logging/leakage
- rate-limit sensitive authentication routes and avoid useful account-enumeration differences
- customer machine credentials are distinct from human browser sessions

The current source has browser-session security tests; do not infer cookie correctness from code inspection alone—run them after auth/proxy changes.

## 19. Audit, reports, and protection evidence

The codebase contains audit/protection/reporting surfaces and tests including report authenticity. Where supported, verify integrity/signing behavior, tenant correctness, timestamp semantics, and redaction.

Reports/evidence must never contain raw customer credentials or authentication tokens. A signed report proves integrity of the represented evidence; it does not by itself prove that every external source/provider observation was complete.

## 20. Guard/package expectations

When producing a customer-facing Guard package, prefer a versioned artifact and immutable image tag rather than `latest`. The customer package must not accidentally ship the source repository or secrets.

Expected operational concepts include install/enroll/start/stop/status/logs/health/upgrade/uninstall/support-bundle behavior where implemented. Upgrade should preserve durable Guard identity/configuration/policy/audit state. Uninstall should not silently purge durable state unless purge is explicitly requested.

## 21. Recent implementation history useful for orientation

Recent commits before this snapshot show the progression of the current architecture:

```text
ab59ffd Harden Guard concurrency and durable recovery
1af8916 Assert browser console and network health
a125302 Add dedicated Golden authorization scenarios
e3c6124 Speed up test-only authentication fixtures
ce50814 Strengthen Protect readiness checks
108c8ce Add customer-facing authorization protection surfaces
1baf42e Add complete Microsoft permission-source integration parity
c0352b4 Add source credential renewal path
9ecec60 Add real target and Drive-backed integration suite
39b108c Upgrade real target PoC to proof-grade validation
50d90b7 Add real RAG target validation PoC
510fd7e Add Google Drive permission source automation
3f60b72 Guard revocation enforcement
4b3200b Guard Layer 2 provenance checks
c9d199d Guard policy synchronization and acknowledgements
7baabb6 Guard policy-cache install hardening
aefb36a Add durable Guard policy cache and Layer 1
f0064dd Baseline: verified Guard persistence, authentication, and local connector flow
```

## 22. Safe operating commands

### Local development

```bash
cd /home/white-devil/Downloads/accessproof/f15
git status --short
git branch --show-current
git rev-parse HEAD
docker compose ps
```

Use project-declared commands/scripts for tests and builds. Inspect `pyproject.toml`, `Makefile`, `web-v2/package.json`, Playwright config, and CI before inventing commands.

### Production inspection

On the EC2 host:

```bash
cd /home/ubuntu/accessproof
docker compose -f docker-compose.ec2.yml config --services
docker compose -f docker-compose.ec2.yml ps
```

Production mutation/deployment requires explicit user approval. Read-only inspection, logs, health checks, and configuration verification are preferred first.

Never use routine/destructive cleanup such as:

```text
docker system prune -a
docker volume prune
rm -rf <broad path>
DROP DATABASE
```

Never print `.env` or secret values while debugging. Verify variable presence/configuration without revealing the value.

## 23. Release/test loop

For a comprehensive engineering pass, use this loop:

```text
INSPECT
→ RUN
→ reproduce failure
→ ROOT-CAUSE
→ SMALLEST CORRECT FIX
→ TARGETED TEST
→ RELATED TESTS
→ CONTINUE SUITE
→ FULL REGRESSION
→ if failure: repeat
→ if green: release verification
```

Release-critical local gates include, where configured:

- full backend suite
- Guard suite
- Golden authorization scenarios
- PostgreSQL concurrency matrix
- Redis/worker durable recovery
- connector/unit/integration/security suites
- web-v2 lint/typecheck/tests/build
- Playwright browser tests including console/network health
- Docker image builds
- Compose validation
- Nginx/config validation
- package/checksum validation if Guard packaging is being released

Never use “probably fixed” when the behavior can be tested.

## 24. Readiness language

Do not conflate local code quality with full production/customer proof.

A valid local verdict, only after all local release-critical gates are green, is:

```text
ACCESSPROOF LOCAL PRODUCTION CANDIDATE READY
```

Otherwise use:

```text
ACCESSPROOF LOCAL PRODUCTION CANDIDATE NOT READY
```

Real provider/customer validation should be reported separately.

## 25. Final continuity rule

This document exists so a fresh ChatGPT session can rapidly recover the product model and locate the real system. It is **not** a substitute for inspecting the current repository.

When a future assistant is asked to debug, upgrade, test, or deploy AccessProof, it should first read this file, then confirm current Git/diffs/config/database/deployment state, and only then act.

**Evidence over assumptions. Source code over stale documentation. Preserve user work. Protect customer data and secrets.**
