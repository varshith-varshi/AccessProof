# Evidence and Report Verification

**Implemented:** 2026-10-24 · checkout `ab59ffd` + current worktree

## Purpose and scope

Control-plane reports export the authorization evidence AccessProof actually
holds for one tenant. They are **not** a blanket security certificate and must
not be used to imply that an unenrolled route, unsupported adapter, or
uncertified provider is protected.

Each report separates four evidence levels:

| Report field | Meaning |
|---|---|
| `control_plane_state` | Directly observed by AccessProof (enrollment, configuration, sync cursors, source status). |
| `guard_decisions` | Asserted by the enrolled customer-side Guard through authenticated uploads. The control plane does not independently replay them. |
| `provider_effective_permissions` | Confirmed only for sources with an independent provider certificate; otherwise `NOT_OBSERVED`. |
| `revocation_to_first_denial_timing` | Always `NOT_OBSERVED` unless a separate measured experiment is attached. |

## API

All routes require `REPORT_READ` and are scoped to the actor’s organization.

| Method | Path | Behavior |
|---|---|---|
| `POST` | `/api/v1/current/reports` | Generates and signs a report. Body: `{"report_type": "APPLICATION_COVERAGE" \| "GUARD_HEALTH" \| "AUTHORIZATION_ACTIVITY"}`. Returns `201` with `{report, signature, verification}`. |
| `GET` | `/api/v1/current/reports` | Lists the 100 most recent reports for the tenant (summary only). |
| `GET` | `/api/v1/current/reports/{report_id}` | Reads `{report, signature, verification}`. |
| `GET` | `/api/v1/current/reports/{report_id}/verify` | Recomputes signature, scope and expiry. |
| `GET` | `/api/v1/current/reports/{report_id}/download` | Returns a JSON attachment, audits `report.downloaded`, and sets `Cache-Control: private, no-store`. |

Machine API keys may read/verify/download with the `reports:read` scope.
Report generation remains interactive-session-only.

Storage limits:

- 30-day expiry (`_CONTROL_PLANE_REPORT_TTL_DAYS = 30`).
- Maximum 200 stored reports per tenant. Generating beyond that returns HTTP
  `429 REPORT_STORAGE_LIMIT`. There is no automatic deletion of customer
  evidence.
- Rows cascade-delete when the organization is deleted; deleting a user sets
  `generated_by_user_id` to `NULL`.

## Schema (`accessproof.control_plane_report/v1`)

Top-level fields include:

```json
{
  "schema": "accessproof.control_plane_report/v1",
  "report_id": "<uuid>",
  "report_type": "APPLICATION_COVERAGE",
  "organization_id": "<tenant>",
  "generated_by_user_id": "<user>",
  "generated_at": "<ISO-8601>",
  "expires_at": "<ISO-8601>",
  "product": "<product name>",
  "signer_role": "accessproof-control-plane",
  "data_cutoff": "<ISO-8601>",
  "scope": {"tenant_scoped": true, "applications": [], "guards": [], "sources": []},
  "evidence_levels": {},
  "summary": {},
  "applications": [],
  "guards": [],
  "sources": [],
  "decisions": {"aggregate_24h": {}, "recent": []},
  "limitations": []
}
```

`APPLICATION_COVERAGE` and `GUARD_HEALTH` include per-application state and the
failed-check reasons computed at generation time. `AUTHORIZATION_ACTIVITY`
includes up to 100 recent metadata-only Guard decisions and 24-hour aggregates.

## Privacy controls

- Employee subject IDs are replaced with a 16-character SHA-256-derived
  `subject_ref`; raw identifiers are not exported.
- Resource IDs are not included; only `resource_count` per decision.
- No prompts, retrieved document text, model answers, tokens, credentials, or
  source boundaries are included.
- No raw provider payloads are included; Microsoft evidence is reduced to a
  certificate level.

## Signing and verification

Signing uses `packages/crypto/signing.py` (`Ed25519Signer` derived from the
server `REPORT_SIGNING_KEY`). The signed manifest contains:

```json
{
  "algorithm": "Ed25519",
  "key_id": "ed25519:<16-hex>",
  "payload_sha256": "<sha256 of canonical JSON>",
  "public_key": "<base64url raw public key>",
  "signature": "<base64url signature>"
}
```

Canonical JSON means `sort_keys=True`, compact separators, UTF-8. The server
verifies:

1. payload hash matches,
2. Ed25519 signature validates against the embedded public key,
3. derived key ID matches,
4. report schema, report ID, type and organization match the stored row,
5. the report has not expired.

An expired report may still have a valid signature; `verified` is `false` and
`expired` is `true`. Historical verification must not be presented as current
protection.

### Offline verifier

```bash
python scripts/verify_control_plane_report.py \
  ./accessproof-application_coverage-<report-id>.json \
  --expected-organization <org-id> \
  --expected-report-type APPLICATION_COVERAGE \
  --expected-key-id ed25519:<key-id>
```

Exit codes: `0` verified, `1` verification failed, `2` unreadable input.
`--allow-expired` verifies the signature of an archived report while still
reporting expiry. The verifier uses only the public key in the envelope and
never contacts the server.

## Tests

| Test | Coverage |
|---|---|
| `tests/integration/test_control_plane_reports.py` | Generation, signature verification, listing, download, tamper rejection, expiry, tenant isolation, privacy limitations, dashboard `NO_DATA` |
| `tests/unit/test_verify_control_plane_report.py` | Offline verifier: valid, tampered, expired, key/type/org pinning, malformed envelope |

## Explicit limitations

- A report reflects **current backend state at generation time**; it is not a
  route certificate and expires.
- Guard decisions are customer-machine assertions.
- Provider effective permissions are `NOT_OBSERVED` unless separately
  certified.
- Revocation-to-first-denial timing is never inferred from configuration,
  heartbeats, or the mere absence of denials.
- PDF export, external timestamping, and third-party attestation are not
  implemented.
