# AccessProof full security audit — 2026-11-03

**Scope:** `apps/api`, `apps/worker`, `apps/guard`, `apps/gateway`,
`packages/rag_core`, `packages/crypto`, `web-v2`, `migrations`, `packaging`,
`deploy`, `tests`.

**Method:**
1. Source review.
2. Adversarial tests in an isolated environment (synthetic tenants, identities,
   keys and documents).
3. The full test suite on SQLite, and on PostgreSQL 17 with the API connected
   as the restricted `accessproof_app` role.
4. A dependency audit.

**Not performed:** live production or real-tenant testing (see the blockers in
`ACCESSPROOF_FINAL_SECURITY_ASSESSMENT.md`).

## Feature inventory and verified status

"Local" means verified by automated tests at this commit. **Nothing in this
column has been verified in production.**

| Feature | Implementation | Local verification | Security notes |
|---|---|---|---|
| Registration, email verification | `/auth/signup`, `/auth/verify-email` | Tests pass | Unverified users are blocked from all org APIs |
| Login, sessions | `/auth/login`, DB sessions; HttpOnly cookie plus CSRF double-submit | Tests pass | Rate limits keyed on the trusted-proxy client IP; XFF spoofing held |
| MFA (TOTP + recovery codes) | `/auth/mfa/*` | Tests pass | **RT-03 fixed:** codes are now single-use |
| Password reset / change | `/auth/forgot-password`, `/auth/reset-password` | Tests pass | Single-use, 30-minute token; all sessions revoked |
| Organizations and workspaces | `/organization`, `/auth/me` | Tests pass | Rename is admin-only and audited |
| Team invitations and roles | `/organization/invitations`, `/members` | Tests pass | Email-bound and single-use; ownership transfer blocked; no escalation |
| API keys | `/api-keys` | Tests pass | Scope ∩ live role; downgrading the creator removes authority |
| Source connect/disconnect | `/current/sources`, Microsoft admin consent | Tests pass | Consent redirect host is pinned; credentials are encrypted |
| SharePoint ACL sync | `acl_sync.py`, worker | Tests pass (simulated Graph) | Links, guests and site-local principals refused (tests added); **live: BLOCKED** |
| Guard install, registration, readiness | Guard app, enrollment, heartbeat | Tests pass | Readiness is computed, never hardcoded; production refuses static identity |
| Gateway install, pairing, heartbeat | `gateway_presence`, installer | Tests pass | Monotonic, tenant-scoped heartbeat; archiving revokes the credential |
| RAG integration | Gateway chat routes, adapters | Tests pass (in-process model) | **Live: BLOCKED** |
| Layer 1 / Layer 2 | `packages/rag_core/protection.py` | Tests pass | Revision binding L1 == L2; buffered release |
| Revocation and cache | Authorization revisions, signed cache manifests | Tests pass (simulated provider) | Every cache hit is re-authorized; **latency unmeasured** |
| Certificate verification | Ed25519, public key only in the API | Tests pass (test key) | No production certificate exists |
| Application archive/restore | `/current/ai-applications/{id}/archive` | Tests pass | Soft archive; revokes Gateway; clears pairing |
| Onboarding reset | Owner-only preview and execute with TOTP step-up | Tests pass | Step-up now replay-safe |
| Website and dashboard | Next.js 16 `web-v2` | Playwright | **RT-01 fixed:** open redirect |
| Background sync | Worker | Tests pass | Runs as `accessproof_rls_admin` (no BYPASSRLS) |
| Deployment and rollback | `deploy/ec2-release/*` | Rehearsal on a stand-in | D-09…D-13 found and fixed; **not run on production** |
| Tenant isolation (DB) | Forced RLS; 3 restricted roles | Full suite on PostgreSQL as `accessproof_app` | P0-01; switch not applied in production |

## Findings
See `ACCESSPROOF_VULNERABILITY_REGISTER.md` (generated from `findings.json`).
* New in this assessment:
  * RT-01 (P2): post-login open redirect.
  * RT-02 (P2): JWKS refetch amplification.
  * RT-03 (P3): TOTP replay.
  * RT-04 (P1): vulnerable dependencies.
  * RT-05 (P3, open, dev-only): npm dev-tooling advisories.
* Carried over and fixed: P0-01 and D-05…D-13.

## Compatibility note from the dependency upgrade (RT-04)
FastAPI 0.162 / Starlette 1.10 reject a JSON body sent **without**
`Content-Type: application/json` (HTTP 422).
* AccessProof's own clients (the Guard client, the Gateway, the runner) always
  send it.
* Nine test harnesses that relayed requests without it were corrected.
* A customer integration that posts JSON to the Gateway without the header
  will now receive 422 and must add it. Announce this in the release notes.

## Supply chain
* `pip-audit`: 0 known vulnerabilities after the upgrade (60 before).
* `npm audit --omit=dev`: 0. The 16 moderate advisories are in dev tooling
  only.
* The Guard and Gateway Docker images install from `pyproject.toml` and pick
  up the new floors only when rebuilt. The customer Guard tarball 0.1.5
  predates this and must be rebuilt.
