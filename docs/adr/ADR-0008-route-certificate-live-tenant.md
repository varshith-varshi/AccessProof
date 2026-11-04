# ADR-0008: Route certificates in a live tenant (D-26)

**Status:** implemented 2026-11-04 (r33 candidate). **Needs reviewer acceptance before any Protect activation.**

## Problem
The reference-route challenge was designed against a synthetic Guard. In a production tenant it could never certify:
1. The route fingerprint included the Guard's `active_policy_version`. That version advances on every ACL change, every few minutes in a live tenant, and also on the challenge's own `layer2_revoke` revocation. So the challenge was refused at submit and any route certificate expired almost immediately.
2. A Guard with authorization revisions (all production Guards) reports an access change between Layer 1 and Layer 2 as `AUTHORIZATION_REVISION_CHANGED` (Gateway 503), because the revision check runs before the per-decision recheck. The verifier accepted only 403 `LAYER2_ACCESS_REVOKED`.
3. The agent's 12 s HTTP timeout could not span a real revocation window.

## Decision
* **The fingerprint binds configuration only:** organization, application, Guard, source, adapter and contract version. Changing any of these still invalidates the certificate.
* **Rollback protection is kept:** at verification the control plane records `guard_policy_version_at_verification`. A certificate is invalid if the Guard later reports a lower policy version (reset, re-enrolment, rollback), or if no version was recorded.
* **`layer2_revoke` accepts exactly two outcomes:** `(403, LAYER2_ACCESS_REVOKED)` and `(503, AUTHORIZATION_REVISION_CHANGED)`. The observed reason must equal the Guard's **own audited** Layer 2 block reason for the same decision and subject as the Layer 1 allow. Mismatched pairs, generic outages and unaudited claims are refused.
* **The agent timeout is configurable** (1–120 s, default 12 s).

## Unchanged
Nonce binding, one-time use, the 10-minute expiry, the deployment and route hashes, the installer contract and network-isolation check, Guard machine authentication, Guard-audit corroboration of all four probes, the policy version upper bound per audit event, `CERTIFICATE_TTL`, and the separate cutover step.

## Still required before gate E can pass
The live challenge must run against a Gateway deployed through the **reference installer**. The agent verifies the installer manifest hashes and model-egress isolation. The lab Gateway was paired manually and has no installer manifest, so it cannot be certified until it is re-deployed that way.
