# Run local adversarial tests without touching production

```bash
cd /home/white-devil/Downloads/accessproof/f15
# tests/conftest.py substitutes process-unique SQLite databases, including Guard cache.
# The Ubuntu host has an unrelated ROS pytest hook; disable its autoload:
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
.venv/bin/python -m pytest -p pytest_asyncio.plugin \
  tests/security/test_adversarial_guard_boundaries.py \
  tests/security/test_adversarial_sdk_contract.py \
  tests/security/test_policy_ordering.py \
  tests/security/test_release_version_race.py \
  tests/unit/test_drive_rag_guard_path.py -q
.venv/bin/python -m pytest -p pytest_asyncio.plugin tests -q --disable-warnings --tb=short
.venv/bin/ruff check apps/guard/accessproof_guard/app.py \
  apps/guard/accessproof_guard/cache.py packages/rag_sdk/protection.py \
  tests/security/test_adversarial_guard_boundaries.py \
  tests/security/test_adversarial_sdk_contract.py
git diff --check
```

Safety: `tests/conftest.py` forces ephemeral SQLite `DATABASE_URL`, Guard cache and credentials path at module import before API code. Never run the suite with a production database, untrusted arbitrary external plugins, or a shared customer test tenant. Use generated JWTs and canaries only. Existing CI `.github/workflows/ci.yml` runs full `pytest` on pushes/PRs; new tests under `tests/security/` are picked up by existing discovery. Provider tests require separate opt-in authorization.

**Checkpoints:** Red evidence `/tmp/accessproof_h01_red.log`, `/tmp/accessproof_redteam_first6.log`, `/tmp/accessproof_sdk_adversarial_red.log`; focused greens `/tmp/accessproof_redteam_postfix.log`, `/tmp/accessproof_adversarial_targeted_latest.log`, `/tmp/accessproof_previous_full_failures_recheck.log`. Temp logs are local and not immutable audit proof.

## Run the 2026-10-20 audit-continuation tests

From the project root, with only ephemeral local SQLite fixtures and synthetic credentials:

```bash
TMPDIR=/dev/shm env -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -p pytest_asyncio.plugin tests/security/test_audit_backpressure.py tests/security/test_audit_backpressure_http.py tests/security/test_audit_health.py tests/security/test_binding_health_defaults.py -q
TMPDIR=/dev/shm env -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -p pytest_asyncio.plugin -q
.venv/bin/ruff check .
.venv/bin/mypy apps packages connectors integrations
git diff --check
```

CI .github/workflows/ci.yml already runs the complete pytest discovery on pushes/PRs; these new tests are automatically included. Do not run against live customer or production databases. New tests intentionally use isolated temporary SQLite databases and synthetic tokens.

## 2026-10-20 new local security regressions
Run from repository root with PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 and TMPDIR=/dev/shm:

    .venv/bin/pytest -q -p pytest_asyncio.plugin tests/security/test_chunk_trace_reauthorization.py tests/security/test_stable_subject_configuration.py tests/security/test_mfa_recovery_code_replay.py
    .venv/bin/pytest -o addopts='' -q -p pytest_asyncio.plugin tests --disable-warnings --tb=short
    .venv/bin/ruff check apps/api/accessproof_api/app.py apps/guard/accessproof_guard/app.py apps/guard/accessproof_guard/identity.py apps/guard/accessproof_guard/onboarding.py packages/rag_sdk/protection.py tests/security/test_chunk_trace_reauthorization.py tests/security/test_stable_subject_configuration.py tests/security/test_mfa_recovery_code_replay.py
    git diff --check

All scenarios use generated synthetic credentials, in-memory HTTP mocks, isolated test SQL databases; no real customers or Google accounts.
