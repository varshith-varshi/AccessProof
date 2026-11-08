from __future__ import annotations

import pytest

from scripts.drills.postgres_isolation_restore_drill import guard_disposable


@pytest.mark.parametrize("url", [
    "postgresql+psycopg://u:p@db.prod.internal:5432/accessproof_drill",   # non-loopback
    "postgresql+psycopg://u:p@127.0.0.1:5432/accessproof",                 # not a drill database
    "postgresql+psycopg://u:p@10.0.0.5/drill",
])
def test_drill_refuses_non_disposable_databases(url):
    with pytest.raises(SystemExit):
        guard_disposable(url)


def test_drill_accepts_loopback_drill_database():
    guard_disposable("postgresql+psycopg://u:p@127.0.0.1:55432/accessproof_drill")
