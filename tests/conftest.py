"""Keep the test suite isolated from developer and deployed databases.

This module is imported by pytest before application test modules.  The API
configuration is read during module import, so the database URL must be set
here rather than in a fixture.  A process-unique SQLite database lets tests
that deliberately reset schema state run safely even when ``.env`` points at
the local Compose PostgreSQL service.
"""

from __future__ import annotations

import atexit
import os
import tempfile
from pathlib import Path


_fd, _path = tempfile.mkstemp(prefix="accessproof-pytest-", suffix=".db")
os.close(_fd)
_database_path = Path(_path)
os.environ["DATABASE_URL"] = f"sqlite:///{_database_path}"
os.environ["ACCESSPROOF_ENV"] = "development"
# Standalone legacy Guard fallback is forbidden by default, even on a host
# missing production configuration. The disposable pytest suite explicitly
# opts in; deployed customer Guards MUST enroll and sync app bindings.
os.environ["ACCESSPROOF_GUARD_STANDALONE_TEST_MODE"] = "1"
# Account creation is exercised hundreds of times in the integration suite.
# Production retains the default 310,000 PBKDF2 rounds because this variable is
# only supplied by the test harness.
os.environ["ACCESSPROOF_TEST_PASSWORD_ITERATIONS"] = "1000"
_guard_fd, _guard_path = tempfile.mkstemp(prefix="accessproof-guard-", suffix=".db")
os.close(_guard_fd)
_guard_cache_path = Path(_guard_path)
os.environ["ACCESSPROOF_GUARD_CACHE"] = str(_guard_cache_path)
# Never let a developer's enrolled Guard credentials start a real control-plane
# synchronizer from a unit-test TestClient.  Individual tests provide the
# isolated settings they need through monkeypatching.
_credential_fd, _credential_path = tempfile.mkstemp(prefix="accessproof-guard-credentials-", suffix=".json")
os.close(_credential_fd)
_credential_path = Path(_credential_path)
os.environ["ACCESSPROOF_GUARD_CREDENTIAL_FILE"] = str(_credential_path)


@atexit.register
def _remove_test_database() -> None:
    _database_path.unlink(missing_ok=True)
    _guard_cache_path.unlink(missing_ok=True)
    _credential_path.unlink(missing_ok=True)
