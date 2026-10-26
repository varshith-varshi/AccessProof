"""Explicit operator-only provisioning of the signed PostgreSQL cache table.

Example:
ACCESSPROOF_DEMO_CACHE_BACKEND=postgresql \
ACCESSPROOF_DEMO_CACHE_SQLALCHEMY_URL=postgresql+psycopg://... \
python -m packages.demo_cache.provision

Do not run against a production database without owning the chosen schema
and getting the database administrator's approval.
"""
from packages.demo_cache.factory import configured_cache_backend
from packages.rag_sdk.cache_backends import SQLAlchemyBackend


def main() -> None:
    backend = configured_cache_backend()
    if not isinstance(backend, SQLAlchemyBackend):
        raise SystemExit("CACHE_POSTGRESQL_BACKEND_REQUIRED")
    backend.provision_schema()
    print("ACCESSPROOF_SIGNED_CACHE_SCHEMA_READY")


if __name__ == "__main__":
    main()
