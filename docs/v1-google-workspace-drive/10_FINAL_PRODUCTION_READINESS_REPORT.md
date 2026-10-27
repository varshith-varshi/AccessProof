# Google Workspace + Drive V1 readiness report

## Verified locally

V1 production scope enforcement, browser credential rejection, source lifecycle behavior, tenant isolation, Google OAuth flow tests, protected source health tests, Python compilation and the `web-v2` production build have been executed locally.

## Not yet externally proven

This repository is **not cleared for unrestricted customer production claims** until the live Workspace checklist is completed. The remaining proof points are Google’s real effective authorization behavior, direct/nested group revocation propagation, Shared Drive/link-sharing semantics, real OAuth operational configuration, and a customer RAG adapter’s identity/provenance enforcement.

## Staging command

Set `ACCESSPROOF_STAGING_SESSION_TOKEN` to a short-lived staging-only operator session token through your secrets runner (never put it on the command line), then run:

`python scripts/validate_google_v1_staging.py --api-url https://api.staging.example --organization-id ORG_ID`

Alternatively pipe the token through standard input using `--token-stdin`. The checker requires a strict HTTPS origin, refuses redirects, and prints redacted source/Guard health counts instead of records. It is diagnostic evidence only, not Protect certification.

The command is read-only. It intentionally cannot replace the manual tests in the live checklist.
