# AccessProof V4 — Route Certification and Revocation Evidence

**Snapshot:** 2026-10-24
**Scope:** machine-observed reference-route certification, signed authorization
revisions, the six-timestamp revocation timeline, and bounded metrics.

## 1. Reference-route certificate

Implementation: [apps/api/accessproof_api/route_certification.py](../../apps/api/accessproof_api/route_certification.py).
Surfaced in `GET /api/v1/current/ai-applications/{id}/protection/status`, the
Protection overview, and `web-v2/app/protection/page.tsx`.

A certificate is bound to the exact:

```text
organization + application + Guard + source + adapter + contract version
+ active Guard policy version
```

via `route_configuration_fingerprint`. The certificate is derived from a
nonce-bound Gateway challenge and matching Guard audit evidence. It expires
after **24 hours**.

| Status | Meaning |
|---|---|
| `NOT_APPLICABLE` | Adapter is not `accessproof-gateway`; no reference-route claim applies. |
| `MISSING` | No current challenge evidence, or the Guard is not enrolled/ready. |
| `TESTED_NOT_CUTOVER` | Challenge probes passed but the customer's real route cutover is not verified. |
| `CERTIFIED` | Challenge passed and the customer cutover request/deny/tamper evidence was verified under the current fingerprint. |
| `EXPIRED` | A prior challenge exists but is older than 24 hours or the Guard policy/configuration changed since it was issued. |

Fields include `certificate_id`, `configuration_fingerprint`, `verified_at`,
`cutover_at`, `expires_at`, `age_seconds`, `evidence_level`
(`PRODUCTION_OBSERVED` when observed), `independent_certification` (always
`false`), `certification_scope` (`REFERENCE_GATEWAY_ROUTE_ONLY`) and explicit
limitations.

A certificate proves only the documented Gateway route exercised by the
challenge. It does **not** discover or certify arbitrary application APIs, SSE,
WebSocket, tool, cache, or background-worker paths, and it is not an independent
customer certification.

## 2. Signed authorization revisions

Implementation: [apps/api/accessproof_api/authorization_revision.py](../../apps/api/accessproof_api/authorization_revision.py)
and [apps/guard/accessproof_guard/cache.py](../../apps/guard/accessproof_guard/cache.py).

- A revision is a tenant/application-scoped monotonic number generated from
  stable authorization inputs (ACL/directory revisions, policy version, route
  binding, adapter contract).
- Revisions are Ed25519-signed and hash-chained through
  `previous_revision_hash`.
- Reusing unchanged state reuses the revision; any relevant change allocates a
  new monotonic revision. Forks (same number, different hash) and stale
  revisions are rejected by the Guard cache.
- The control plane exposes `GET /api/v1/current/authorization-revisions`
  (authenticated, tenant-scoped) and the Guard syncs the signed snapshot.
- A Protect binding without a current revision fails closed
  (`AUTHORIZATION_REVISION_MISSING`).

### Guard-reported revision acknowledgement

Guards include `active_authorization_revisions` in the machine-authenticated
heartbeat. The control plane accepts only:

- applications bound to that Guard in that tenant (otherwise
  `AUTHORIZATION_REVISION_APPLICATION_NOT_BOUND`);
- exact revision numbers and hashes that were issued
  (otherwise `AUTHORIZATION_REVISION_NOT_ISSUED`).

It stores the report for revision-lag measurement. A heartbeat is an
acknowledgement of revision use, not proof of a correct decision; the revocation
timeline uses the first authenticated Layer 1 audit under the exact revision
instead.

## 3. Six-timestamp revocation timeline

Implementation: [apps/api/accessproof_api/revocation_timeline.py](../../apps/api/accessproof_api/revocation_timeline.py).
Endpoint: `GET /api/v1/current/revocation-timeline?application_id=...`
(permission `AUDIT_READ`, tenant-scoped, max 50 retained events).

| Timestamp | Source |
|---|---|
| `provider_permission_mutation_at` | Provider-supplied mutation time, only when the event carries it. |
| `provider_change_observed_at` | AccessProof observation time of the permission event. |
| `acl_state_committed_at` | Completion time of the normalized ACL transaction. |
| `authorization_revision_created_at` | First signed revision generated at or after the ACL commit. |
| `guard_revision_applied_at` | First authenticated Layer 1 allow under that exact revision. |
| `first_verified_denial_at` | First blocking Layer 1 audit after the ACL commit matching the revoked subject or resource. |

Rules:

- A missing timestamp is `NOT_OBSERVED` with a source explanation — never
  inferred from an unrelated event.
- An unrelated denial is not counted as the revocation's first denial.
- `complete` is true only when all post-observation timestamps are observed.
- Employee, resource and file identifiers are used for matching but are never
  returned.
- Only retained permission events and Guard audit rows are represented.

## 4. Metrics with absence semantics

Implementation: [apps/api/accessproof_api/observability.py](../../apps/api/accessproof_api/observability.py).
Database-backed gauges are refreshed immediately before the `/metrics` scrape.

| Metric | Meaning |
|---|---|
| `accessproof_source_freshness_seconds{provider}` | Worst-case age of a trusted ACL sync. |
| `accessproof_directory_freshness_seconds{provider}` | Worst-case age of a trusted directory sync. |
| `accessproof_provider_event_lag_seconds{provider}` | Largest observed provider-observation-to-receipt delay. |
| `accessproof_route_certificate_age_seconds` | Age of the oldest current reference-route certificate. |
| `accessproof_protected_route_coverage_ratio` | Protect-bound applications with a current certificate ÷ Protect-bound applications with reference-route eligibility. |
| `accessproof_guard_revision_lag_seconds` | Time since the newest revision while a Guard reports an older issued revision. |
| `accessproof_authz_decision_total{layer,result,reason}` | Machine-authenticated Guard decisions. |
| `accessproof_layer2_block_total{reason}` | Layer 2 blocked releases. |
| `accessproof_cache_reauth_total{result}` | Protected cache-hit reauthorization outcomes. |
| `accessproof_revocation_end_to_end_seconds` | Observed provider-change-to-first-denial duration, from retained evidence. |

A gauge with no sample means **no retained evidence**; it is not fabricated as
zero. Labels are bounded and contain no tenant, application, Guard, subject,
resource, or document identifiers.

## 5. Capability registry and release vocabulary

- Canonical registry: [packages/capability_registry.py](../../packages/capability_registry.py).
- API: `GET /api/v1/current/capabilities` (permission `RESULT_READ`).
- Export: `scripts/export_capability_registry.py --format json|csv`.
- Committed matrix: [03_FEATURE_AND_CAPABILITY_MATRIX.csv](03_FEATURE_AND_CAPABILITY_MATRIX.csv).

Evidence levels: `UNIT_VERIFIED`, `LOCAL_INTEGRATION_VERIFIED`,
`CONTRACT_SIMULATED`, `LIVE_PROVIDER_VERIFIED`,
`INDEPENDENT_CUSTOMER_VERIFIED`, `STAGING_VERIFIED`, `PRODUCTION_OBSERVED`.

The static registry is not a per-tenant certificate and currently contains no
live provider/customer evidence. `release_gate()` returns `LAB` as eligible;
`CONSTRAINED_PILOT` and `CERTIFIED_PROFILE` are refused until live evidence
exists; `NO_GO` remains available. Microsoft 365 is not Protect-eligible, and
PDF evidence packages, native streaming, WebSocket, tools, Kubernetes and
independent certification are explicitly unsupported.

## 6. Tests

```bash
.venv/bin/python -m pytest tests/integration/test_route_certificate_state.py -q
.venv/bin/python -m pytest tests/integration/test_rag_route_challenge_api.py -q
.venv/bin/python -m pytest tests/integration/test_revocation_timeline_api.py -q
.venv/bin/python -m pytest tests/integration/test_guard_revision_reporting.py -q
.venv/bin/python -m pytest tests/integration/test_capability_registry.py -q
.venv/bin/python -m pytest tests/integration/test_observability.py -q
```

Coverage includes certificate expiry/configuration change, cutover lifecycle,
timeline observed/not-observed and tenant isolation, heartbeat revision
rejection and lag measurement, capability registry honesty and release-gate
refusals, and metrics naming/absence behavior.

## 7. Residual gates

1. Obtain a live customer route challenge with independent cutover evidence;
   the current certificate remains local/reference evidence.
2. Prove every active customer response path (SSE, cache, tools, workers) is
   covered or explicitly outside the Protect claim.
3. Measure live provider mutation and denial timing; no live provider was used
   in this build.
4. PostgreSQL/pgvector, multi-worker and production observability remain
   unverified.
