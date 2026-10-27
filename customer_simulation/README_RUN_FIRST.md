# Customer digital twin

Generating a scenario catalogue does not execute the scenarios; all generated rows initially have NOT_TESTED results. The real test evidence is stored separately.

Run `python -m customer_simulation.harness.digital_twin` to regenerate the synthetic corpus and evidence, then run `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TMPDIR=/dev/shm .venv/bin/pytest -q -p pytest_asyncio.plugin tests/integration/test_customer_lifecycle_over_http.py tests/integration/test_synthetic_customer_http_boundary.py tests/unit/test_google_drive_v1_security.py tests/unit/test_directory_connectors.py tests/unit/test_oauth_refresh.py`. All data is synthetic; do not put credentials in this directory.
