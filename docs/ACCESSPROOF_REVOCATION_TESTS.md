# Revocation tests (2026-11-02)

## Local (PASS)

* Permission event → resolved policy → new authorization revision → Guard
  install → deny: `test_customer_lifecycle_over_http.py` (HTTP lifecycle with
  a synthetic provider), `test_revocation_timeline_api.py`,
  `test_microsoft_group_multi_member_revocation.py`.
* Equal or older revision replay cannot restore access:
  `test_adversarial_equal_revision_replay.py`, `test_twin_acl_revision_replay.py`.
* Revision change between Layer 1 and Layer 2 blocks release:
  `test_authorization_revision_binding.py`.
* Cached answer after revocation is re-authorized and denied:
  `test_cached_answer_protection.py`.

## Live (BLOCKED)

| Scenario | Status | Dependency |
|---|---|---|
| Direct revoke on `finance_alice.txt` (list item 2), restore | BLOCKED | Owner authorization to run `scripts/sharepoint_synthetic_revocation_trial.py --execute --acknowledge-synthetic`, plus tenant credentials on the authorized workstation |
| Group/library/folder removal, account disable | BLOCKED | Same |
| Revoke during retrieval / inference / before release | BLOCKED | Live Gateway with employee OIDC |
| **Propagation latency** | **NOT MEASURED** | No number is claimed |

No latency figure is reported because none was measured.
