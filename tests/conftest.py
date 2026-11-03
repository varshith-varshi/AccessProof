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
# P0-01 PostgreSQL mode: the application under test connects as the
# restricted runtime role, while schema resets run as the owner and re-apply
# the canonical tenant policies. Enabled only when both URLs are supplied.
_PG_OWNER_URL = os.environ.get("ACCESSPROOF_TEST_PG_OWNER_URL", "")
_PG_APP_URL = os.environ.get("ACCESSPROOF_TEST_PG_APP_URL", "")
_PG_WORKER_URL = os.environ.get("ACCESSPROOF_TEST_PG_WORKER_URL", "")
if _PG_OWNER_URL and _PG_APP_URL:
    # Module-level SessionLocal is used by worker code and by tests that
    # inspect rows directly: it runs as the cross-tenant worker role. Every
    # API request (Depends(get_db)) runs as the restricted application role.
    os.environ["DATABASE_URL"] = _PG_WORKER_URL or _PG_APP_URL
    if os.environ.get("ACCESSPROOF_TEST_PG_METRICS_URL"):
        os.environ["ACCESSPROOF_METRICS_DATABASE_URL"] = os.environ["ACCESSPROOF_TEST_PG_METRICS_URL"]
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


if _PG_OWNER_URL and _PG_APP_URL:
    from sqlalchemy import MetaData, create_engine

    _owner_engine = create_engine(_PG_OWNER_URL)
    _original_create_all = MetaData.create_all
    _original_drop_all = MetaData.drop_all

    def _is_app_database(bind) -> bool:  # type: ignore[no-untyped-def]
        # Only the application's own PostgreSQL engine is redirected; tests
        # that deliberately use a private SQLite database are left alone.
        return bind is None or getattr(getattr(bind, "dialect", None), "name", "") == "postgresql"

    def _owner_create_all(self, bind=None, *args, **kwargs):  # type: ignore[no-untyped-def]
        from apps.api.accessproof_api.db_security import apply_tenant_policies, grant_runtime_privileges
        if not _is_app_database(bind):
            return _original_create_all(self, bind, *args, **kwargs)
        _original_create_all(self, _owner_engine, *args, **kwargs)
        with _owner_engine.begin() as connection:
            apply_tenant_policies(connection)
            grant_runtime_privileges(connection)

    def _owner_drop_all(self, bind=None, *args, **kwargs):  # type: ignore[no-untyped-def]
        if not _is_app_database(bind):
            return _original_drop_all(self, bind, *args, **kwargs)
        _original_drop_all(self, _owner_engine, *args, **kwargs)

    MetaData.create_all = _owner_create_all  # type: ignore[method-assign]
    MetaData.drop_all = _owner_drop_all  # type: ignore[method-assign]


if _PG_OWNER_URL and _PG_APP_URL and _PG_WORKER_URL:
    from collections.abc import Iterator

    from sqlalchemy import event
    from sqlalchemy.orm import sessionmaker

    from apps.api.accessproof_api.app import app as _api_app
    from apps.api.accessproof_api.auth import get_db as _get_db
    from apps.api.accessproof_api.db import _apply_rls_context

    _app_engine = create_engine(_PG_APP_URL, pool_pre_ping=True)
    _AppSession = sessionmaker(bind=_app_engine, autoflush=False, expire_on_commit=False)
    event.listen(_AppSession, "after_begin", _apply_rls_context)

    def _app_role_db() -> Iterator[object]:
        db = _AppSession()
        try:
            yield db
        finally:
            db.close()

    _api_app.dependency_overrides[_get_db] = _app_role_db
