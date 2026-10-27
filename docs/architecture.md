# AccessProof final architecture

Status date: 2026-09-30

## 1. Control plane

The FastAPI control plane is a modular monolith backed by SQLAlchemy/Alembic. It owns authentication, organizations/RBAC, projects, source connections, AI targets, identities, suites/scenarios, releases, run queue state, runner identities/leases/checkpoints, mutation journals, cleanup tasks, reports, audit events, alerts, entitlement/usage records, email/webhook outboxes and retention/deletion state.

The Next.js web app, CLI and CI integrations all consume `/api/v1` rather than duplicating product logic.

## 2. Authentication and tenancy

Interactive users use password/TOTP or OIDC. Browser sessions use HttpOnly cookies plus CSRF protection; CLI/CI can use bearer sessions or hashed scoped API keys. Organization membership and role policy are validated server-side for every tenant-owned request. Application-layer tenant-isolation tests cover guessed/cross-tenant object access. PostgreSQL RLS is intentionally not claimed because no separate non-owner runtime-role implementation was validated.

## 3. Secret architecture

Secret storage is abstracted. Development can use AES-GCM local encryption. Production can use AWS KMS envelope encryption, where KMS generates/wraps a fresh data key and only the wrapped key+ciphertext is persisted. Secrets are not returned by read APIs and logging/tracing intentionally excludes credential/header content.

## 4. Test engine

The engine uses one provider-independent state machine and normalized source adapter API. A scenario selects a mutation path and synthetic-data family. Core lifecycle:

1. validate capability/preconditions;
2. create a unique synthetic source resource and canary;
3. verify allowed identity retrieves the canary;
4. verify denied control cannot retrieve it;
5. persist destructive mutation intent/checkpoint;
6. perform the provider mutation;
7. confirm authoritative source ground truth;
8. repeatedly probe the AI target;
9. detect deterministic answer/citation/retrieval/tool exposure;
10. require stable denial;
11. compute provider, propagation and exposure timing from confirmed source change;
12. classify PASS/FAIL/INCONCLUSIVE/PRECONDITION_FAILURE/ERROR/CANCELED;
13. clean up exact tracked resources;
14. persist evidence/report integrity material.

The engine does not use an LLM as the security oracle. Optional LLM probes only expand synthetic questions; deterministic probes and deterministic exposure signals remain mandatory.

## 5. Source adapters

All providers implement normalized capabilities and resource/access operations. Capability states include SUPPORTED, UNSUPPORTED, MISSING_SCOPE, PLAN_RESTRICTED, EXPERIMENTAL, NOT_IMPLEMENTED and PROVIDER_DEPRECATED.

Current adapters include Microsoft 365/SharePoint, Google Drive, Confluence Cloud, Slack and Salesforce plus a full mock provider. Provider-specific semantics are preserved rather than flattened into a fake universal ACL model.

## 6. AI target architecture

The generic HTTP target supports controlled request/response mapping and none/bearer/API-key/basic/OAuth-client authentication plus private-runner mTLS. Cloud-mode target URLs must be public HTTPS and pass SSRF/DNS-address validation; private/internal endpoints require runner mode.

## 7. Private runner and crash safety

The runner registers using a one-time token, receives a long-lived revocable credential, heartbeats, checks version compatibility and leases strongly typed jobs over outbound HTTP. Checkpoints and a mutation journal persist the destructive boundary. Expired leases can be reclaimed. Recovery will not blindly replay an acknowledged mutation; tracked provider resources are re-adopted only when their metadata matches the configured test boundary.

## 8. Cleanup

Every synthetic provider resource is tracked by exact provider ID and AccessProof ownership metadata. Terminal paths produce cleanup state. Failed cleanup creates durable cleanup work for the janitor. Name similarity alone is never sufficient authorization to delete a resource.

## 9. Release regression and CI

Runs carry release/git/environment metadata. The regression layer supports previous-successful, pinned and manual baselines, absolute/percentage latency deltas, new failure/inconclusive detection and capability loss. REQUIRED/OPTIONAL/INFORMATIONAL scenarios feed the release decision engine. CLI/GitHub/GitLab integrations use the same API and exit semantics.

## 10. Evidence and reports

Normalized state transitions and evidence items feed JSON/HTML/PDF/JUnit/SARIF representations. Source ground truth is shown separately from AI observations. Failure-boundary diagnostics state only what evidence supports. Report manifests include hashes and a digital signature; integrity verification detects modified payloads.

## 11. Audit, retention and deletion

Audit rows are append-oriented in ordinary ORM operation. Security/auth/configuration/run/report/runner changes are recorded without secrets. Organization retention policy is processed by a scheduled worker. Project/organization deletion checks active work, clears associated secrets/data according to policy and records deletion receipts.

## 12. Alerts and delivery

Alerts are deduplicated and use durable transactional email/webhook outboxes with retry/backoff. Current alert types cover security/SLO regressions, runner health and delivery failures. Webhooks are signed with replay protection.

## 13. Observability

The service emits structured logs/correlation IDs, Prometheus-style metrics, health/live and dependency-aware health/ready. OpenTelemetry span hooks avoid sensitive content; collector/exporter deployment remains environment-specific.

## 14. Deployment

The repository contains web/API/worker/runner Dockerfiles and Compose infrastructure for PostgreSQL/Redis. Docker runtime validation could not be executed in this environment because Docker is unavailable. Kubernetes/Helm remains deliberately deferred until container runtime validation is possible.
