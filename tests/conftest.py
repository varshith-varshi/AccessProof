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


@atexit.register
def _remove_test_database() -> None:
    _database_path.unlink(missing_ok=True)
