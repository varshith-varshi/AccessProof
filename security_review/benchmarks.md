# Benchmark ledger — not yet production benchmarking

Environment: authorized local Ubuntu desktop; Python 3.12 virtualenv, ephemeral SQLite test databases, HTTP mock transports. Tool runner had unrelated ROS pytest plugin autoload conflict; `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` resolved it.

Evidence:
- Initial targeted security baseline: **54 passed**, exit 0, in approximately 53s wall time (includes test collection and API test startup, NOT per-decision authorization latency).
- New focused Guard/cache/SDK suite: **38 passed**, exit 0.
- Current added adversarial tests: **21 passed**, exit 0 (before the later rerun incorporating additional fixes).
- After the final cache-ordering security fix, the full local Python suite completed **343 passed, 4 warnings, exit 0 in 10.35s** (`/tmp/accessproof_adversarial_verified_latest.log`).
- Web-v2 Playwright E2E completed **21 passed, 1 skipped**, exit 0 (`/tmp/accessproof_adversarial_web_e2e.log`). This does not measure production authorization latency.

Not measured: per-request p50/p95/p99, load throughput, memory, multi-tenant concurrency under realistic resource limits, Guard recovery time and real Drive revoke → denial percentiles. Budgets not invented. A benchmark remains **BLOCKED/UNVERIFIED** until isolated, reproducible measurements exist.

## Latest local verification — 2026-10-20

- Full Python suite: **350 passed**, exit 0, executed with process-isolated SQLite and synthetic Guard credentials.
- Focused adversarial Guard/SDK/chunk suite: **27 passed**, exit 0.
- `ruff check apps connectors packages tests integrations`: **PASS**.
- Scoped Mypy for the changed SDK/Guard paths: **PASS**.
- `web-v2` ESLint, TypeScript typecheck and production build: **PASS**.
- Playwright web-v2: **21 passed, 1 skipped**. The skipped case remains unverified.

These are correctness/security-regression results, not latency or throughput benchmarks.

## Audit continuation 2026-10-20

Full Python tests exit 0; 349 tests collected at final collection. Final repository-wide mypy: 95 source files pass. Ruff, TypeScript SDK (4 pass), Next.js lint/typecheck/build, Docker Compose config and diff check pass. Playwright: 21 pass and 1 skip. The checks are correctness and smoke-test evidence; they do NOT measure production p50/p95/p99, 24/7 availability, Drive propagation latency or sustained HA recovery. None were measured in this continuation.
