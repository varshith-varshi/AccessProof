# SharePoint authorization (2026-11-02)

## Decision model in code

`ALLOW` requires all of the following:

* a verified employee OIDC identity (`sub`/`oid`);
* a control-plane mapping to the SharePoint principal (Graph-verified
  immutable Entra object ID, not email);
* a Guard policy entry for (source, resource, principal);
* a fresh ACL cursor (≤ 900 s) and directory cursor (≤ 2400 s) with no errors;
* no unresolved permission events and no undelivered policy;
* a current authorization revision; and
* **for Microsoft sources, a valid effective-permission certificate for this
  exact tenant/site/list/drive/root scope**.

Anything missing or stale → `DENY` / 503. Graph sharing records alone never
grant Protect.

## Certificate trust chain (after D-01)

```
live checks (tenant + real route)  ──►  evidence.json (14 required checks, all PASS, ≤72h)
                                              │
              certifier host (holds Ed25519 private key, never the API)
              scripts/issue_source_certificate.py issue  ──►  signed record
                                              │
              scripts/issue_source_certificate.py import  (re-verified by API logic)
                                              ▼
API: ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON  ──►  effective_source_certified()
```

Required checks: `PROVIDER_EFFECTIVE_PERMISSION_MATRIX`,
`EMPLOYEE_OIDC_POSITIVE_IDENTITY`, `EMPLOYEE_OIDC_SECOND_IDENTITY`,
`IDENTITY_MAPPING_IMMUTABLE_OBJECT_ID`, `INHERITED_AND_GROUP_PERMISSIONS`,
`PROVIDER_REVOKE_OBSERVED`, `PROVIDER_RESTORE_OBSERVED`,
`GATEWAY_ROUTE_AUTHORIZED_RELEASE`, `GATEWAY_ROUTE_UNAUTHORIZED_DENIED`,
`GATEWAY_POST_REVOCATION_DENIED`, `GATEWAY_INFLIGHT_REVOCATION_DENIED`,
`CACHED_ANSWER_REUSE_DENIED`, `PROVENANCE_TAMPER_REJECTED`,
`BUFFERED_RELEASE_VERIFIED`.

Validity is at most 14 days (default 7), so recertification is periodic by
design.

## Current live status

* Reported by the prior team on 2026-11-02: a certificate-backed SharePoint
  REST effective-permission matrix passed 6/6 for Alice/Bob ×
  finance/engineering/shared. **Not re-verified here.**
* Missing: interactive employee OIDC, an authorized revoke/restore on the
  synthetic site, and protected-route tests. **No certificate may be issued
  until these exist.** Production Protect for SharePoint therefore remains
  blocked, as it must.
* The production flags `…MICROSOFT_SHADOW_ONBOARDING_ENABLED` and
  `…MICROSOFT_CERTIFIED_PROTECT_ENABLED` remain separate in code
  (`config.py`). Their current production values could not be read.
