"""One-command read-only health validation for a configured cache connector.

Does not print connection strings, passwords or cached customer content.
Does not initialize database tables or mutate customer cache entries.
"""
from __future__ import annotations

from packages.demo_cache.factory import CacheConfigurationError, configured_cache_backend
from packages.rag_sdk.cache_backends import CacheBackendError


def main() -> int:
    try:
        connector = configured_cache_backend()
        if connector is None:
            print("CACHE_CONNECTOR_NOT_CONFIGURED")
            return 2
        if not connector.ping():
            print("CACHE_CONNECTOR_NOT_READY")
            return 1
        print("CACHE_CONNECTOR_READY")
        return 0
    except (CacheConfigurationError, CacheBackendError, ValueError):
        print("CACHE_CONNECTOR_NOT_READY")
        return 1
    except Exception:
        print("CACHE_CONNECTOR_NOT_READY")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
