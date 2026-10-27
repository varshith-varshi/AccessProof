# Multi-source authorization — Guard V2 (2026-10-27)

## Scope and status
A single AI application can now register multiple **explicitly approved** enterprise source bindings. This is locally implemented and tested. It is **not** evidence of live Microsoft 365/Google interoperability or customer-route certification.

## Trusted source bindings
The control plane stores `AIApplicationSourceBinding` records in `ai_application_source_bindings`. Alembic `n7a2b4c6d801` migrates legacy `AIApplication.source_id` into one explicit binding without deleting that field. The Guard synchronizer receives `source_ids`, `source_health` and the backward-compatible primary `source_id`, installed atomically in `bound_applications` / `bound_application_sources`.

An application-level authorization revision hashes *all* its source cursor states plus Guard policy version and binding; it is required before V2 Protect accepts a request. Source ACL/directory health must be fresh for **every** bound source. An unhealthy or missing source fails closed. The Guard maps verified immutable JWT issuer/tenant/subject to a distinct source ACL principal for each requested source. No shared email-ID assumption is permitted.

## Protocol
Use POST `/guard/v2/filter-resources` with `application_id`, `request_id`, and `resources`, each containing `source_id`, `resource_id`, `content_version`, optional `chunk_ids` and `scope="read"`. Content versions are mandatory on V2. The return includes `allowed` and `denied`, one-time `decision_id`, application revision number and hash. Gateway calls the model only with allowed, attested chunks.

Use POST `/guard/v2/check-output` with matching `decision_id`, `application_id`, `request_id`, `used_resources`, and `provenance`. Each dependency contains its source ID, resource ID, chunk ID and content version. All used resources must be covered by matching source-qualified lineage. The Guard atomically consumes the decision context in SQLite while checking each stored source-specific identity, binding, revision, health and current ACL. Contexts are bound to a SHA-256 of verified issuer/tenant/subject and expire after five minutes; retries cannot replay a consumed context.

V1 `/guard/v1/filter-resources`, `/guard/v1/check-output`, and `/guard/v1/authorization-scope` deny when the application has more than one source. They **must not** interpret V2 contexts.

## Gateway behavior
When a protected request contains more than one source, the Gateway calls V2 and never silently falls back to V1. On a multi-source application where the user selects *only one* source, set `ACCESSPROOF_GATEWAY_MULTISOURCE_GUARD_V2=true` for the enrolled Gateway to force V2. One-source legacy registrations retain V1 by default.

Guard denies when:
- Source ID not bound, identity mapping missing or mismatched, JWT invalid or tenant mismatch.
- No current source ACL health or revision, stale policy sync, no resources authorized.
- An unauthorized resource appears in output, source/content/chunk IDs collide, context expires or is replayed.
- A grant changes or source/identity mapping is removed before release.

## Explicit limitations
- No independently proven atomic boundary at the upstream provider commit instant; AccessProof guarantees checks against its latest installed authoritative policy, subject to synchronization latency.
- Gateway V2 requires independently signed source snapshots. Existing customer retrieval middleware may require integration work to supply content provenance.
- V2 presently supports bounded, buffered, text RAG and source-qualified read access. V2 late tool dependencies and V2 ANN authorization-scope retrieval are not implemented. Existing conversation history is blocked on mixed-source V2 routes until authorized dependency lineage can be attached and rechecked.
- Multi-source end-to-end customer challenge/cutover certification and live Microsoft/Google results remain blocked or untested; control-plane Protect preflight refuses unverified multi-source routes.
