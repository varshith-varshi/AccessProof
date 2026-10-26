# Security model

## Trust boundaries

AccessProof separates the cloud control plane, customer private runner, external source provider and customer AI target. Internal AI endpoints are contacted by the runner rather than by the SaaS control plane.

## Tenant isolation

Every exposed tenant query is filtered by the authenticated membership organization. The browser-supplied `X-Organization-ID` is not sufficient: membership is checked server-side. Cross-tenant run retrieval is covered by an automated no-metadata-leakage test. PostgreSQL RLS is recommended as defense-in-depth but is not enabled in this build; see `IMPLEMENTATION_STATUS.md`.

## Credentials

Passwords use PBKDF2-SHA256 with per-password salts. Session/API/registration/invitation/reset tokens are cryptographically random and persisted only as SHA-256 hashes. Provider secrets and TOTP seeds use AES-GCM authenticated encryption under a key supplied separately from the database. Recovery codes are stored only as hashes.

## Mutation safety

A source connection requires an explicit boundary and a mutation acknowledgement. Adapters track concrete provider resource IDs. SharePoint/Google/Confluence/Salesforce adapters refuse deletion of resources not created by the adapter instance. The product should be used against dedicated test resources and sandboxes, not arbitrary production content.

## SSRF

Cloud AI targets must use HTTPS. DNS resolution is inspected and private, loopback, link-local, multicast and reserved addresses are rejected. Redirects are disabled. Private targets require runner mode.

## Evidence minimization

The engine stores hashes, canary matches, timestamps and evidence-level classification by default. Report serialization redacts the canary value. Raw customer AI responses are not persisted by the current engine.

## Webhooks

Webhook payloads are canonicalized and signed with HMAC-SHA256 over `timestamp.payload`. Verification includes a replay window. Delivery uses a durable outbox and bounded retries.

## PostgreSQL row-level security

PostgreSQL deployments enable and force tenant RLS on project/run/evidence/report and related operational tables. API requests set `accessproof.organization_id` inside the current transaction after receiving the requested organization ID and still perform normal application-layer membership/RBAC checks. Runner-authenticated control-plane requests set the same context only after the runner credential is validated. The background worker uses the server-controlled `ACCESSPROOF_RLS_BYPASS=1` process setting so janitor, retention, alert and delivery jobs can reconcile multiple tenants; this variable must never be exposed to the web/API deployment. RLS is defense-in-depth, not a replacement for application authorization.
