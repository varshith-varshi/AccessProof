# AccessProof SharePoint validation — 2026-11-03

## Verdict: SHAREPOINT PRODUCTION PROTECT — NOT VERIFIED

**No live Microsoft operation was performed in this assessment.** This
session's network policy denies `graph.microsoft.com`, `api.accessproof.in`
and `app.accessproof.in`, and AWS STS rejects the available credentials
(`InvalidClientTokenId`). `login.microsoftonline.com` is reachable, but only
for public OIDC discovery, which proves nothing about Alice, Bob or the
SharePoint site.

Every live item below is therefore **BLOCKED**, not passed. Local results are
labelled LOCAL: they use synthetic identities, keys and documents, and are
evidence about the *code*, not about the tenant.

| Status | Meaning |
|---|---|
| PASS-LOCAL | Automated test at this commit, synthetic data, isolated environment |
| BLOCKED | Requires the real tenant, real employees or production; not performed |
| N/A | Not part of the supported scope; verified to fail closed |

## 4.1 Microsoft tenant configuration — BLOCKED
* Reference tenant `6479e7ca-b256-4ebc-a408-871b9046547c`. Its OIDC discovery
  endpoint answered 200, which shows the tenant exists and nothing more.
* App registration, client ID, redirect URIs, Graph permissions, admin consent
  and per-site grants were **not inspected**. That needs Entra admin portal or
  Graph access.
* **Evidence required:**
  * An export of the app registration (`/applications/{id}`) showing redirect
    URIs and `requiredResourceAccess`.
  * The service principal's `appRoleAssignments` (admin consent).
  * `Sites.Selected` grants (`/sites/{id}/permissions`) proving the app is
    limited to the lab site.
* **Code-level controls (PASS-LOCAL):**
  * Consent redirects are pinned to `https://login.microsoftonline.com`.
  * Graph tokens never follow redirects
    (`test_graph_app_token_does_not_follow_untrusted_redirect_from_injected_client`).
  * Provider credentials are encrypted at rest.

## 4.2 Entra employee authentication — PASS-LOCAL / live BLOCKED
* **PASS-LOCAL** (`tests/security/test_entra_identity_negative_matrix.py`, 19 tests):
  * Rejected: expired, wrong tenant, missing `tid`, wrong audience, a Graph
    access token, wrong issuer, a v1 (`sts.windows.net`) issuer, a forged
    signature, an unknown `kid`, `nbf` in the future, missing `exp`, missing
    `oid`, `alg=none`, and HS256 key confusion.
  * Only `oid`/`sub` can be the subject, never email.
* **Fixed (RT-02):** unknown-`kid` tokens could force an IdP key fetch on every
  request.
* **BLOCKED:** real Alice and Bob sign-in. **Evidence required:** a Guard audit
  record per employee showing verified `iss`/`tid`/`oid` and the identity
  mapping (`GuardIdentityMapping` status VERIFIED, tenant-bound) for both.

## 4.3 Site and library discovery — BLOCKED
* Reference site `neuralmatrix093.sharepoint.com`, drive
  `8200ffae-ba10-42c5-bfa9-8f7ac155c5c4`. Not re-verified.
* **PASS-LOCAL:**
  * Provider-ID path delimiter injection is rejected
    (`test_microsoft_recovery_rejects_provider_id_path_delimiters`).
  * Cross-source and cross-drive references are blocked by source-qualified
    lineage.
* **Evidence required:** a live discovery transcript (site ID, drive ID, root
  item ID), plus negative probes against a second, unauthorized site returning
  403/404.

## 4.4 Document indexing — BLOCKED
* **PASS-LOCAL:**
  * Content attestation (Ed25519) binds tenant, application, source, resource,
    chunk and version.
  * A forged or replayed attestation is blocked before the model
    (`test_c06_forged_provenance_is_blocked_and_context_cannot_be_replayed`).
* **Evidence required:** ingestion records for `finance_alice.txt`,
  `engineering_bob.txt` and `shared_control.txt` with eTags and attestation
  key IDs, followed by an update, a move and a delete, each showing the old
  chunk rejected.

## 4.5 Effective permission model — BLOCKED (critical)
* The Graph `permissions` collection is **not** treated as complete effective
  access.
* The design requires corroboration through the source certificate's 14
  `REQUIRED_CHECKS`. No certificate exists, so the model is **unproven on the
  real tenant**.
* Categories and their state:

  | # | Category | Local | Live |
  |---|---|---|---|
  | 1 | Direct user | PASS-LOCAL | BLOCKED |
  | 2 | File-specific | PASS-LOCAL | BLOCKED |
  | 3 | Folder | PASS-LOCAL | BLOCKED |
  | 4 | Inherited | PASS-LOCAL | BLOCKED |
  | 5 | Library | PASS-LOCAL | BLOCKED |
  | 6 | Site | PASS-LOCAL | BLOCKED |
  | 7 | Entra security group | PASS-LOCAL (`test_microsoft_group_identity_confusion.py`) | BLOCKED |
  | 8 | M365 group | PASS-LOCAL | BLOCKED |
  | 9 | Nested groups | PASS-LOCAL (supported depth) | BLOCKED |
  | 10 | Guests | Out of certified scope; fails closed: siteUser-only, email-only and ambiguous principals are refused (PASS-LOCAL, `tests/unit/test_sharepoint_link_and_guest_grants_fail_closed.py`) | BLOCKED |
  | 11 | Sharing links | Out of certified scope; fails closed: anonymous, organization, specific-people and existingAccess links are refused (PASS-LOCAL, same file; test added in this assessment) | BLOCKED |
  | 12–16 | Inheritance change, explicit removal, group removal, move, delete | PASS-LOCAL | BLOCKED |

## 4.6 Alice/Bob matrix — LOCAL ONLY
* **PASS-LOCAL**, on a synthetic replica of the matrix
  (`tests/security/test_participant_aware_authorization.py`):

  | Document | Alice | Bob |
  |---|---|---|
  | finance | ALLOW | DENY |
  | engineering | DENY | ALLOW |
  | shared | ALLOW | ALLOW |

* This includes the positive paths, so the system does **not** simply block
  everything.
* **BLOCKED** three times over: directly in SharePoint, through AccessProof
  against the real source, and through the real protected RAG.

## 4.7 Permission synchronization — PASS-LOCAL / live BLOCKED
* Local coverage:
  * Delta tokens, 410/expired delta, 429/5xx retry, out-of-order revisions
    (`revision_replay`, `equal_revision`), BIGINT provider revisions (D-05).
  * A failed sync marks the source stale and fails closed.
* **Evidence required:** a measured run against the tenant, from a permission
  change through the Graph delta, a new authorization revision and a Guard
  policy acknowledgment.

## 4.8 Revocation tests A–G — BLOCKED
* Local, simulated provider: in-flight revocation, cached-answer revocation
  and restoration are covered by existing tests.
* **No latency was measured.** No SLO is claimed.
* **Evidence required:** for each of tests A–G, the seven timestamps in Part
  4.8 from the authorized trial on the lab site.

## 4.9 Guard — PASS-LOCAL / live BLOCKED
* Local: wrong identity is denied, an unauthorized file is denied, a revoked
  file is denied, and a stale policy, invalid certificate or unavailable Guard
  fails closed.
* Rehearsal gate D failed honestly: no live Guard was attached.

## 4.10 Gateway — PASS-LOCAL / live BLOCKED
* Local:
  * Authenticated heartbeat with monotonic sequence.
  * A rebinding forces re-pair, and archiving revokes the credential.
  * Buffered release and the Layer 1 == Layer 2 revision binding hold.
* **Not testable without the customer host:** direct-route bypass resistance,
  meaning whether another published endpoint reaches the model.

## 4.11 RAG end-to-end — BLOCKED
* All ten required outcomes hold locally, using an in-process model stand-in.
* A mock model is **not** evidence for the live path. No live answer was
  produced.

## 4.12 Customer onboarding — PASS-LOCAL (UI) / live BLOCKED
* Playwright covers registration, verify, login, invitations, settings and the
  application list.
* Fixed (RT-01): the post-login open redirect.

## 4.13 Independent certification — BLOCKED
* The certifier and the API's public-key-only verification are PASS-LOCAL.
* No certifier key exists, and no certificate has been issued. **None was
  fabricated.**

## 4.14 Evidence files
The JSON files in this directory hold one record per required test, with the
Part 4.14 fields. Live records carry `status: "BLOCKED"`, `actual_decision:
null` and `evidence_hash: null`, because nothing was observed.

## What clears this (operator actions, in order)
1. Give this or another session network access to `graph.microsoft.com` and
   the production hosts, plus valid AWS credentials. Alternatively, run the
   steps from an operator machine.
2. Deploy (`ship_via_ssm.sh`). With owner approval, run the least-privilege
   switch.
3. Alice and Bob sign in through Entra.
4. Run the authorized revoke/restore trial on the lab site (tests A–G).
5. Generate the certifier key off-host, collect the 14 checks, then issue and
   import the certificate.
6. Run `run_security_gates.sh` with the evidence file.
7. Record reviewer approval.
