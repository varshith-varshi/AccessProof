#!/usr/bin/env bash
# Offline artifact validation + isolated HTTP simulation. Never mutates production.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZIP="${1:?Usage: smoke_customer_onboarding.sh ZIP_PATH FULL_SHA256}"
SHA="${2:?Usage: smoke_customer_onboarding.sh ZIP_PATH FULL_SHA256}"
cd "$ROOT"
"$ROOT/.venv/bin/python" scripts/smoke_gateway_customer_zip.py \
  --zip "$ZIP" --expected-sha256 "$SHA" \
  --current-source apps/gateway/accessproof_gateway/challenge_cli.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TMPDIR=/dev/shm \
  "$ROOT/.venv/bin/python" -m pytest -q -p pytest_asyncio.plugin \
  tests/unit/test_gateway_customer_zip_smoke.py \
  tests/unit/test_gateway_customer_install_path.py \
  tests/unit/test_gateway_challenge_cli.py \
  tests/unit/test_gateway_customer_zip_multiapp.py \
  tests/unit/test_gateway_zipapp_doctor.py \
  tests/integration/test_gateway_presence.py \
  tests/integration/test_guard_enrollment_api.py \
  tests/integration/test_rag_route_challenge_api.py
printf '\nONBOARDING_SMOKE_PASS: published artifact checks + isolated HTTP regressions.\n'
printf 'NOT TESTED: fresh external Docker host, Microsoft admin consent, live employee route, Owner approval.\n'
