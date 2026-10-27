"""Operator-only one-shot expired signed SQL answer cache janitor.

Can run via the customer's approved periodic scheduler; never mutates data
outside the dedicated AccessProof signed-answer cache table.
"""
from __future__ import annotations

from packages.demo_cache.factory import configured_cache_backend
from packages.rag_core.cache_backends import SQLAlchemyBackend, CacheBackendError


def main() -> int:
    try:
        cache = configured_cache_backend()
        if not isinstance(cache, SQLAlchemyBackend):
            print("CACHE_SQL_JANITOR_BACKEND_REQUIRED")
            return 2
        deleted = cache.purge_expired(limit=1000)
        print(f"CACHE_EXPIRED_ROWS_DELETED={deleted}")
        return 0
    except (CacheBackendError, ValueError):
        print("CACHE_SQL_JANITOR_FAILED")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
