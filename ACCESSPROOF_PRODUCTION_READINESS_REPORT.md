# NeuralMatrix AccessProof — Production Readiness Report

**Date:** 2026-11-02  **Determination:** **NOT_READY**  **Signed:** No
**Nature:** internal engineering assessment. This is *not* an independent
certification or accreditation.

## A. Executive summary

The code implements the two-layer design correctly in every path reviewed:
unauthorized chunks are removed before the model call, model context is built
only from verified and attested allow-listed bytes, the answer is buffered,
and release requires Layer 2 with matching authorization revisions. The full
automated suite passes locally (1313 passed, 0 failed, 4 skipped).

This session fixed four defects:

* **D-01:** the API could mint its own SharePoint certificates.
* **D-02:** Gateways had no authenticated liveness.
* **D-03:** a production Guard accepted shared-secret identities and reported ready.
* **D-04:** undecryptable Microsoft credentials crashed activation checks.

The product is **not ready**. The real protected-RAG acceptance test has
never passed, SharePoint Protect is (correctly) blocked pending live
certification evidence, and production, AWS and the tenant were unreachable
from this environment, so nothing was deployed or verified live.

## B. Architecture and trust boundaries

See `docs/ACCESSPROOF_ARCHITECTURE_AUDIT.md` and
`docs/ACCESSPROOF_SECURITY_THREAT_MODEL.md`.

## C. Feature coverage

See `docs/ACCESSPROOF_FEATURE_MATRIX.md`. No feature is VERIFIED or
PRODUCTION_CERTIFIED. Onboarding reset is NOT_IMPLEMENTED.

## D. Security assessment

Authentication, authorization, provenance, revocation, cache and route
controls are present and tested locally. Hardened in this change: certificate
trust (D-01), production identity mode (D-03) and Gateway liveness (D-02).

## E. Test results

`ACCESSPROOF_TEST_RESULTS.json`, generated from JUnit (1317 tests; 1313
passed; 4 skipped: local Ollama ×3, live SharePoint fixture ×1). Live
categories (SharePoint tenant, real RAG, live revocation, production) are
**BLOCKED** and not counted.

## F. Vulnerabilities and defects

`docs/ACCESSPROOF_DEFECT_REGISTER.md`: D-01..D-04 fixed locally; O-01..O-09 open.

## G. Deployment verification

**Not performed.** Production hosts were denied by the session network
policy, and AWS STS rejected the container's credentials. Last reported
production images (prior team, 2026-11-01): API `auth-limiter-r2-20261101`,
web `onboarding-source-r6-20261101`. Not re-observed. Deploying this change
requires migrations `q1a2b3c4d5e6` and `r2b3c4d5e6f7`. Rollback is the
previous images with `alembic downgrade p8c1e2f3a4b5`.

## H. Supported scope

SharePoint Online list-item effective profile (**not certified**); Google
Drive V1 (regression); Gateway contract `accessproof.gateway/v1`;
customer-hosted Guard + Gateway on Docker Compose with one selected chatbot.
OneDrive, Confluence, Slack and Salesforce are unsupported for Protect.

## I. Final determination

| | |
|---|---|
| Product readiness | **NOT_READY** |
| Test-workspace protection state | **Not protected** (last reported `protect_pending`) |
| External certification | None. Review cannot start until live evidence exists |

Path to approval: `docs/ACCESSPROOF_PRODUCTION_READINESS.md`.
