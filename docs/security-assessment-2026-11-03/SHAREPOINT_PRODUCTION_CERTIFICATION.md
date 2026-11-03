# SharePoint production certification — NOT ISSUED

**Status: NOT CERTIFIED.** No certificate was issued, and none can be honestly
issued from this assessment.

The independent certifier (`scripts/issue_source_certificate.py`) signs only
when all 14 `REQUIRED_CHECKS` are `PASS`, fresh (72 hours or less),
scope-matched and artifact-digested. In this assessment every live check is
`BLOCKED`. `BLOCKED` and `NOT_TESTED` never count as `PASS`, so the certifier
would correctly refuse to sign.

| Requirement (Part 4.13) | Status |
|---|---|
| Real source identity | BLOCKED |
| Correct Microsoft tenant | BLOCKED (reference tenant discovery only) |
| Correct source scope | BLOCKED |
| Real Alice identity | BLOCKED |
| Real Bob identity | BLOCKED |
| Effective permission matrix | BLOCKED (PASS-LOCAL on a synthetic replica) |
| Supported inherited/group permissions | BLOCKED (PASS-LOCAL) |
| Real revoke-and-restore evidence | BLOCKED |
| Protected positive-path evidence | BLOCKED |
| Protected negative-path evidence | BLOCKED |
| Layer 1 | BLOCKED (PASS-LOCAL) |
| Layer 2 | BLOCKED (PASS-LOCAL) |
| Cached-answer behaviour | BLOCKED (PASS-LOCAL) |
| In-flight revocation | BLOCKED (PASS-LOCAL) |
| Provenance integrity | BLOCKED (PASS-LOCAL) |
| Gateway route binding | BLOCKED |

**Key handling.** The certifier key must be generated off-host by the owner:
```bash
python scripts/issue_source_certificate.py keygen --private-key certifier.key
```
Only the printed public-key JSON goes into
`ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON`. If signer material is
present in the API environment, verification fails closed by design.
