# Executed test and build evidence — 2026-10-22

| Actual command or check | Result | Evidence |
|---|---|---|
| `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -p pytest_asyncio.plugin -q tests` | **450 passed; 5 third-party deprecation warnings; exit 0** | `/tmp/accessproof_v2_after_certification_full_python_20261022.log` |
| Initial four adversarial regressions before patch | **4 failed as expected (RED)** | `/tmp/accessproof_v2_four_red_20261022.log` |
| Four adversarial regressions after patch | **4 passed (GREEN)** | `/tmp/accessproof_v2_four_green_20261022.log` |
| 54-test focused security compatibility tests | **54 passed** | `/tmp/accessproof_v2_targeted_fixed_20261022.log` |
| Microsoft certificate/legacy mode gate targeted tests | **14 passed** | `/tmp/accessproof_v2_certificate_gate_test_20261022.log` |
| TypeScript SDK `../../web-v2/node_modules/.bin/tsc -p tsconfig.json && node --test test/*.test.mjs` | **7 passed** | `/tmp/accessproof_v2_ts_sdk_all_final_20261022.log` |
| TypeScript strict Protect/chunk regression before fixes | **2 failed as expected (RED)** | `/tmp/accessproof_v2_ts_extra_red_20261022.log` |
| `web-v2/npm run build` | **PASS; 22 routes built** | `/tmp/accessproof_v2_web_after_preflight_20261022.log` |
| `npx playwright test` desktop + mobile | **25 passed; 1 skipped** | `/tmp/accessproof_v2_playwright_full_20261022.log` |
| One-click browser test alone | **2 passed** | `/tmp/accessproof_v2_playwright_oneclick_20261022.log` |
| Fresh isolated SQLite `alembic upgrade head → downgrade b3c5d7e9f103 → upgrade head` | **PASS** | `/tmp/accessproof_v2_new_migration.log` |
| Ruff changed source/regression tests | **PASS** | command output / development transcript |
| `git diff --check` | **PASS** | command output / development transcript |
| Real Google Workspace / Entra / SharePoint / OneDrive | **NOT RUN** | No consented tenant and credentials |
| End-to-end automated private RAG challenge & HTTP output-byte observation | **NOT RUN — protocol not implemented** | See `10_PRODUCTION_GAPS_AND_EXTERNAL_VALIDATION.md` |
| Production PostgreSQL + Redis two-worker concurrency/load/soak | **NOT RUN** | Not validated; do not substitute SQLite |
| New binary Guard release installer / macOS / Windows | **NOT RUN** | No release built |

**Environment detail:** The initially attempted unqualified `pytest` failed at collection because ROS `launch_testing_ros_pytest_entrypoint` registered an incompatible plugin. Tests were rerun with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` and the explicit `pytest_asyncio.plugin`, restoring an isolated reliable test environment. Tests use the isolated per-process SQLite and synthetic Guard credentials from `tests/conftest.py`, never the developer's existing `.env` DB.
