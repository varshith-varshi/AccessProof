"""Explicit, bounded and process-pooled cache connectors for the protected RAG."""
from __future__ import annotations

import os
from functools import lru_cache

from sqlalchemy import create_engine

from packages.rag_sdk.cache_backends import (
    CacheBackend, MemcachedBackend, MemoryBackend, RedisBackend, SQLAlchemyBackend,
)


class CacheConfigurationError(ValueError):
    pass


@lru_cache(maxsize=16)
def _build_backend(
    selected: str, redis_url: str, sql_url: str, memcached_host: str,
    memcached_port: int, environment: str,
) -> CacheBackend:
    """Stable, reusable pools. Never allocate a SQL engine per request."""
    if selected == "redis":
        if not redis_url.startswith(("redis://", "rediss://")):
            raise CacheConfigurationError("CACHE_REDIS_URL_REQUIRED")
        from redis import Redis
        return RedisBackend(Redis.from_url(
            redis_url, socket_connect_timeout=2, socket_timeout=2,
            decode_responses=False, health_check_interval=30,
        ))
    if selected == "memcached":
        if not memcached_host or not 1 <= len(memcached_host) <= 253:
            raise CacheConfigurationError("CACHE_MEMCACHED_HOST_REQUIRED")
        if any(ch in memcached_host for ch in ("/", "@", "?", "#", ":")):
            raise CacheConfigurationError("CACHE_MEMCACHED_HOST_INVALID")
        if not 1 <= memcached_port <= 65535:
            raise CacheConfigurationError("CACHE_MEMCACHED_PORT_INVALID")
        try:
            # PooledClient provides safe concurrent access for RAG requests;
            # regular pymemcache Client instances are not thread safe.
            from pymemcache.client.base import PooledClient  # type: ignore[import-untyped]
        except ImportError as exc:
            raise CacheConfigurationError("CACHE_MEMCACHED_DEPENDENCY_MISSING") from exc
        return MemcachedBackend(PooledClient(
            (memcached_host, memcached_port),
            connect_timeout=2, timeout=2, default_noreply=False,
            max_pool_size=8, pool_idle_timeout=30,
        ))
    if selected == "postgresql":
        if not sql_url.startswith("postgresql+psycopg://"):
            raise CacheConfigurationError("CACHE_POSTGRESQL_URL_REQUIRED")
        engine = create_engine(
            sql_url, pool_pre_ping=True, pool_size=5, max_overflow=5,
            connect_args={"connect_timeout": 3},
        )
        return SQLAlchemyBackend(engine)
    if selected == "memory":
        if environment != "development":
            raise CacheConfigurationError("CACHE_MEMORY_PRODUCTION_UNSUPPORTED")
        return MemoryBackend(max_entries=1024)
    raise CacheConfigurationError("CACHE_BACKEND_UNSUPPORTED")


def configured_cache_backend(config: dict[str, str] | None = None) -> CacheBackend | None:
    values = dict(os.environ if config is None else config)
    selected = values.get("ACCESSPROOF_DEMO_CACHE_BACKEND", "").strip().lower()
    redis_url = values.get("ACCESSPROOF_DEMO_CACHE_URL", "").strip()
    sql_url = values.get("ACCESSPROOF_DEMO_CACHE_SQLALCHEMY_URL", "").strip()
    memcached_host = values.get("ACCESSPROOF_DEMO_CACHE_MEMCACHED_HOST", "").strip()
    provided = {
        "redis": bool(redis_url),
        "postgresql": bool(sql_url),
        "memcached": bool(memcached_host),
    }
    if not selected and not any(provided.values()):
        return None
    if not selected:
        detected = [name for name, exists in provided.items() if exists]
        if len(detected) != 1:
            raise CacheConfigurationError("CACHE_BACKEND_AMBIGUOUS")
        selected = detected[0]
    if any(exists and name != selected for name, exists in provided.items()):
        # Never silently attach the RAG process to one database if the
        # operator configured two competing cache destinations.
        raise CacheConfigurationError("CACHE_MULTIPLE_BACKENDS_CONFIGURED")
    try:
        port = int(values.get("ACCESSPROOF_DEMO_CACHE_MEMCACHED_PORT", "11211"))
    except ValueError as exc:
        raise CacheConfigurationError("CACHE_MEMCACHED_PORT_INVALID") from exc
    return _build_backend(
        selected, redis_url, sql_url, memcached_host, port,
        values.get("ACCESSPROOF_ENV", ""),
    )
