# AccessProof final architecture

Status date: 2026-10-02

## 1. Control plane

FastAPI is the modular-monolith control plane. It owns authentication, organizations/RBAC, projects, source/target configuration, suites/scenarios, releases, runs, runners, checkpoints, mutation journal, cleanup, reports, audit, alerts, entitlements, email/webhook outboxes, SSO/provisioning configuration and retention/deletion state.

The Next.js UI, CLI, GitHub Action and GitLab template all consume the same `/api/v1` APIs.

## 2. Authentication and tenancy

Interactive access supports password/TOTP and OIDC. Browser sessions use HttpOnly cookies plus double-submit CSRF. Machine automation uses hashed scoped API keys. SCIM 2.0 supports organization-scoped user and group provisioning/deactivation/reactivation, discovery endpoints, and safe non-OWNER group-to-role mapping.

Application-layer organization checks remain mandatory. PostgreSQL RLS is additional defense-in-depth for core and safely tenant-addressable tables. The request ORM session stores tenant context and reapplies it at every new PostgreSQL transaction so commits cannot silently drop `SET LOCAL` context. Bootstrap tables whose tenant must first be derived from an opaque token remain protected by application authorization rather than unsafe blanket RLS bypasses.

## 3. Secret architecture

Development can use local AES-GCM authenticated encryption. Production can select AWS KMS envelope encryption with wrapped data keys. Provider credentials, target credentials and one-time message payloads are not logged or returned by read APIs.

## 4. Test engine

One provider-independent state machine drives every supported source. The engine:

1. validates capabilities/preconditions;
2. creates unique synthetic content/canary;
3. proves positive access;
4. proves negative-control denial;
5. checkpoints mutation intent;
6. executes the declared provider mutation;
7. confirms authoritative source ground truth;
8. repeatedly probes the connected AI;
9. records answer/citation/retrieval/tool exposure;
10. requires stable denial;
11. computes provider/propagation/exposure timing;
12. classifies PASS/FAIL/INCONCLUSIVE/PRECONDITION_FAILURE/ERROR/CANCELED;
13. cleans exact tracked resources;
14. persists evidence and signed reports.

The implemented propagation state machine covers loss-of-access transitions:
direct revoke, group-member removal, share-link revoke, parent ACL removal,
resource deletion and resource movement. Direct grant and group-member addition
remain declared scenario vocabulary but are capability-gated as unsupported by
this revocation engine; they are not advertised as locally implemented.

Optional LLM-generated probes use synthetic content only; deterministic probes and a deterministic security oracle remain mandatory.

## 5. Source adapters and factory

Microsoft 365/SharePoint, Google Drive, Confluence, Slack, Salesforce and the mock provider implement one normalized connector SDK. The worker and private runner both construct providers through the same connector factory so capability/configuration flags cannot drift between processes.

Provider semantics are preserved: SharePoint document/group/parent/link behavior, Slack conversations, Salesforce record/share behavior, and Confluence restrictions are not flattened into a fake universal ACL model.

## 6. AI target architecture

Generic HTTP targets support constrained templating, response extraction and none/bearer/API-key/basic/OAuth-client auth. mTLS/private IP/internal DNS are runner-only. Cloud mode validates HTTPS destinations, public address resolution and DNS behavior to reduce SSRF/rebinding risk.

Only GET and POST are accepted. Cloud connections are pinned to the validated
public IP while preserving TLS SNI and the Host header. Redirects, non-2xx
responses, malformed JSON, missing answer mappings and invalid evidence-channel
types are unavailable observations and can never prove denial.

## 7. Private runner and recovery

The outbound runner registers with a one-time token, receives a revocable credential, heartbeats, checks schema/version compatibility and leases strongly typed jobs. Checkpoints and the mutation journal persist the destructive boundary. Reclaimed jobs do not blindly replay acknowledged mutations. Provider resources may be re-adopted only when durable metadata matches the authorized test boundary.

## 8. Cleanup

Synthetic provider resources are tracked by exact provider ID and ownership metadata. Failed cleanup becomes durable janitor work with bounded retries. Name similarity alone never authorizes deletion.

## 9. Releases and CI

Runs carry release/git/environment metadata. Baselines support previous-successful, pinned and manual selection. The regression engine detects SLO violations, absolute/percentage latency regression, newly failing/inconclusive scenarios and capability loss. REQUIRED/OPTIONAL/INFORMATIONAL scenarios feed release decisions and CI exit semantics.

## 10. Evidence and reports

Normalized evidence feeds JSON, HTML, PDF, JUnit and SARIF outputs. Source ground truth is shown separately from AI reality. Signed report manifests include hashes, key ID, public verification material and signature; modified artifacts fail verification.

## 11. Enterprise operations

OIDC, SCIM Users+Groups, scoped API keys, retention, deletion, KMS envelope encryption, transactional email, signed webhooks, alerts, entitlements and audit controls are implemented. SAML is deliberately deferred until a vetted SAML/XML-signature runtime is available.

## 12. Observability

Structured logs, correlation IDs, Prometheus metrics and dependency-aware health endpoints are present. OpenTelemetry spans are instrumented in the test engine and an optional OTLP HTTP exporter can be enabled independently in API/worker/runner services. Traces intentionally exclude prompts, canaries, credentials, authorization headers and raw AI content.

## 13. Web product

The Next.js product source includes dashboard/run evidence views, projects, sources, targets, suites, releases, reports, runners, audit, signup/verification/reset/invitation flows, organization/member controls, mutation kill switch, API keys, webhooks, entitlements, OIDC/SCIM settings and runtime branding.

## 14. Deployment

Separate non-root API, worker, runner and web images are built from lockable inputs.
Docker Compose provides PostgreSQL 17, Redis 7 and the API/worker/web stack with
health-aware startup; host ports bind to loopback and can be overridden. The
runner remains a separate opt-in profile because it requires a registered runner
credential. GitHub CI performs Python quality gates, migrations, frontend
build/E2E and image builds. Kubernetes/Helm remains deliberately deferred.
