# AccessProof threat model — 2026-11-03

## Assets
1. **Enterprise document content** (SharePoint): the primary asset. It must
   reach only employees the source authorizes.
2. **Authorization state:** ACL snapshots, identity mappings, authorization
   revisions, Guard policies, source certificates.
3. **Credentials:**
   * Microsoft app credentials and refresh tokens.
   * Guard and Gateway installation credentials.
   * Sessions, API keys and TOTP secrets.
   * Database roles.
   * Certifier and attestation signing keys.
4. **Tenant boundary:** one customer must never read or affect another.
5. **Evidence integrity:** audit events, certificates, gate reports.

## Trust boundaries and controls

| # | Boundary | Adversary | Primary controls | Tested this assessment |
|---|---|---|---|---|
| B1 | Internet → nginx → API | Unauthenticated attacker | TLS; trusted-proxy XFF; per-IP+email rate limits; CSRF on cookie sessions | XFF spoofing (held), CSRF (held) |
| B2 | API session → tenant data | Authenticated user of another tenant | `X-Organization-ID` membership check per request; forced RLS with a non-superuser role (P0-01) | 1,088-request BOLA sweep (held) |
| B3 | Role → privileged action | Low-privilege member | RBAC per route; owner-only operations; API-key scope ∩ live role | Escalation matrix (held) |
| B4 | Employee → Guard identity | Forged or misdirected token | RS/ES-only JWT, pinned issuer, audience, tenant and `oid`; JWKS from pinned discovery | 16-case negative matrix (held); JWKS amplification (fixed RT-02) |
| B5 | Microsoft Graph → ACL sync | Ambiguous or broad grants | Only explicit, unexpired, named user/group grants; links, guests and site-local principals refused | Link/guest matrix (held; tests added) |
| B6 | Retriever → Gateway | Compromised retriever, poisoned documents | Ed25519 content attestation; Layer 1 per-resource decisions; spotlighting with per-request nonce | Knowledge poisoning (held) |
| B7 | Model output → employee | Exfiltration via markup | Sanitizer v2 (entities, CSS, handlers, URL parsing); buffered release; Layer 2 recheck with revision binding | Real-renderer tests (held) |
| B8 | Shared conversation | Omitted recipient | `single_user` default; Ed25519 adapter-signed roster must equal the verified participants | Forged-roster tests (held) |
| B9 | Gateway → control plane | Replay or impersonation | Per-installation bearer credential, monotonic sequence, binding checks | Replay review (held) |
| B10 | Operator → certification | Self-certification | API holds certifier public keys only; signer material in the API environment fails closed | Trust-boundary tests (held) |
| B11 | Release pipeline → production | Faulty release | Checksummed artifact, pre-migration backup, owner-run migrations, automatic rollback, honest restore | Rehearsal (D-09…D-13 found and fixed) |
| B12 | Dependencies | Known-vulnerable packages | Lockfile and audit | 60 advisories found and fixed (RT-04) |
| B13 | Browser → web app | Phishing via a trusted login link | Same-origin `next=` validation | Open redirect found and fixed (RT-01) |
| B14 | MFA | Observed code reuse | One-time TOTP steps | Replay found and fixed (RT-03) |

## Residual risks (accepted or open)
* **Effective-permission completeness on the real tenant is unproven.** It
  needs live corroboration (gate C). This is the central open risk.
* **Direct-route bypass on the customer host:** whether another published
  endpoint reaches the model can only be checked on that host.
* **Revocation latency is unmeasured.** No SLO is claimed.
* **Answer quality is outside authorization's scope.** A poisoned *authorized*
  document can still mislead the model about content the employee may read.
  It cannot widen what the employee sees.
* The roster-signing adapter does not exist yet. Gateways must stay in
  `single_user` mode.
* There are 16 moderate advisories in dev-only npm tooling (not shipped).
