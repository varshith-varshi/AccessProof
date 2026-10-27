# Local product review — 26 October 2026

Repository: `/home/white-devil/Downloads/accessproof/f15`. Scope: current
Gateway-only architecture and official `web-v2` frontend. Existing uncommitted
work was preserved. No deployment or production database changes were made.

## Confirmed issue and fix

The static Compose isolation validator rejected `seccomp:unconfined` and
`apparmor:unconfined`, but accepted the equivalent equals-delimited options.
This could incorrectly pass its hardening prerequisite for a RAG, Gateway,
or reachable relay configured with a disabled security profile. It is a
validation bypass; this review does not claim a demonstrated container escape.

Six regression cases reproduced the issue before the fix. Security-option
validation is now shared across protected components and reachable peers,
recognizes both delimiters, and rejects malformed option lists consistently.
All 62 network-boundary tests passed after the change.

Changed implementation:
`apps/gateway/accessproof_gateway/network_boundary.py`.
Regressions: `tests/unit/test_gateway_network_boundary.py`.

## Verification

- Python Ruff checks: passed across apps, packages, connectors, integrations,
  tests and the staging diagnostic script.
- Python mypy: passed, 139 source files. Changed module rechecked after fix.
- web-v2 ESLint and TypeScript: passed.
- web-v2 production build and Playwright: 31 passed, 5 skipped. Skips cover
  retired Microsoft onboarding scenarios and a mobile-only assertion on desktop.
- Docker Compose configuration: passed (`docker compose config --quiet`).
- Full Python suite result: recorded below after completion.

The browser tests use their existing fixtures. This does not certify a live
Google tenant, real customer identity/provenance integration, or measured
revocation latency. Those release gates remain as documented in the existing
Gateway-only V1 validation report.
