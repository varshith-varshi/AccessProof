"""Cache-agnostic, fail-closed storage adapters for signed AccessProof answers.

This module handles *storage*, not permission grants. Every cache read must
still go through ProtectedRAG.verify_cached_answer with a fresh employee token.
An adapter cannot capture a bypassing cache-return path in another service.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any, Protocol, runtime_checkable

from sqlalchemy import Column, DateTime, LargeBinary, MetaData, String, Table, delete, select
from sqlalchemy.engine import Engine
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert


class CacheBackendError(RuntimeError):
    """Cache unavailable or its integrity/fail-closed contract is violated."""


@runtime_checkable
class CacheBackend(Protocol):
    def get(self, key: str) -> bytes | None: ...
    def set(self, key: str, value: bytes, ttl_seconds: int) -> None: ...
    def delete(self, key: str) -> None: ...
    def ping(self) -> bool: ...


def _validate(key: str, value: bytes | None = None, ttl_seconds: int | None = None) -> None:
    # Works with Memcached's ASCII key requirements and all SQL dialects.
    if not isinstance(key, str) or not 1 <= len(key) <= 240 or any(
        ord(ch) < 33 or ord(ch) > 126 for ch in key
    ):
        raise CacheBackendError("CACHE_KEY_INVALID")
    if value is not None and (not isinstance(value, bytes) or len(value) > 1_000_000):
        raise CacheBackendError("CACHE_VALUE_INVALID")
    if ttl_seconds is not None and (type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 3600):
        raise CacheBackendError("CACHE_TTL_INVALID")


class RedisBackend:
    def __init__(self, client: Any) -> None:
        self.client = client

    def get(self, key: str) -> bytes | None:
        _validate(key)
        try:
            result = self.client.get(key)
            if result is None:
                return None
            if not isinstance(result, (bytes, str)):
                raise CacheBackendError("CACHE_VALUE_INVALID")
            return result.encode("utf-8") if isinstance(result, str) else result
        except CacheBackendError:
            raise
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc

    def set(self, key: str, value: bytes, ttl_seconds: int) -> None:
        _validate(key, value, ttl_seconds)
        try:
            result = self.client.setex(key, ttl_seconds, value)
            if result is False:
                raise CacheBackendError("CACHE_WRITE_FAILED")
        except CacheBackendError:
            raise
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc

    def delete(self, key: str) -> None:
        _validate(key)
        try:
            self.client.delete(key)
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc

    def ping(self) -> bool:
        try:
            return bool(self.client.ping())
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc


class MemcachedBackend:
    """Requires pymemcache Client configured with noreply=False and timeouts."""

    def __init__(self, client: Any) -> None:
        self.client = client

    def get(self, key: str) -> bytes | None:
        _validate(key)
        try:
            result = self.client.get(key)
            if result is None:
                return None
            if not isinstance(result, bytes):
                raise CacheBackendError("CACHE_VALUE_INVALID")
            return result
        except CacheBackendError:
            raise
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc

    def set(self, key: str, value: bytes, ttl_seconds: int) -> None:
        _validate(key, value, ttl_seconds)
        try:
            # Require server confirmation; a best-effort noreply write is not
            # evidence that the signed answer was actually persisted.
            if self.client.set(key, value, expire=ttl_seconds, noreply=False) is not True:
                raise CacheBackendError("CACHE_WRITE_FAILED")
        except CacheBackendError:
            raise
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc

    def delete(self, key: str) -> None:
        _validate(key)
        try:
            self.client.delete(key, noreply=False)
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc

    def ping(self) -> bool:
        try:
            # 'version' is a bounded, non-mutating operation supported by
            # Memcached. Avoid storing a sentinel to test health.
            return bool(self.client.version())
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc


class MemoryBackend:
    """Thread-safe in-process test/custom-Python adapter (not shared between workers)."""

    def __init__(self, *, max_entries: int = 1024) -> None:
        if not 1 <= max_entries <= 100_000:
            raise ValueError("INVALID_MEMORY_CACHE_LIMIT")
        self._limit = max_entries
        self._lock = RLock()
        self._values: dict[str, tuple[bytes, float]] = {}

    def get(self, key: str) -> bytes | None:
        _validate(key)
        with self._lock:
            item = self._values.get(key)
            if item is None:
                return None
            value, expires_at = item
            if expires_at <= time.monotonic():
                self._values.pop(key, None)
                return None
            return value

    def set(self, key: str, value: bytes, ttl_seconds: int) -> None:
        _validate(key, value, ttl_seconds)
        with self._lock:
            now = time.monotonic()
            for expired in [k for k, (_, expiry) in self._values.items() if expiry <= now]:
                del self._values[expired]
            if key not in self._values and len(self._values) >= self._limit:
                # Evict, never return stale documents from an overflowing
                # in-process cache. A signature is still mandatory for reads.
                self._values.pop(next(iter(self._values)))
            self._values[key] = value, now + ttl_seconds

    def delete(self, key: str) -> None:
        _validate(key)
        with self._lock:
            self._values.pop(key, None)

    def ping(self) -> bool:
        return True


class CallbackBackend:
    """Bridge to a customer's existing Python cache via explicit callbacks.

    Callbacks must implement TTL correctly, return bytes (not object/pickle),
    and raise on failures. This does not automatically intercept other callsites.
    """

    def __init__(
        self, *, read: Callable[[str], bytes | None],
        write: Callable[[str, bytes, int], None],
        remove: Callable[[str], None],
        health: Callable[[], bool],
    ) -> None:
        self._read, self._write, self._remove, self._health = read, write, remove, health

    def get(self, key: str) -> bytes | None:
        _validate(key)
        try:
            raw = self._read(key)
            if raw is not None and not isinstance(raw, bytes):
                raise CacheBackendError("CACHE_VALUE_INVALID")
            return raw
        except CacheBackendError:
            raise
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc

    def set(self, key: str, value: bytes, ttl_seconds: int) -> None:
        _validate(key, value, ttl_seconds)
        try:
            self._write(key, value, ttl_seconds)
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc

    def delete(self, key: str) -> None:
        _validate(key)
        try:
            self._remove(key)
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc

    def ping(self) -> bool:
        try:
            return self._health() is True
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc


metadata = MetaData()
signed_cache_entries = Table(
    "accessproof_signed_cache_v1",
    metadata,
    Column("cache_key", String(240), primary_key=True),
    Column("value", LargeBinary(1_000_000), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
)


class SQLAlchemyBackend:
    """PostgreSQL/SQLite signed cache. Table provisioning is an explicit action.

    Use a dedicated customer-controlled DB/schema. This never scans or mutates
    a customer's existing cache table, and does not deserialize pickles.
    """

    def __init__(self, engine: Engine) -> None:
        if engine.dialect.name not in {"postgresql", "sqlite"}:
            raise ValueError("CACHE_DATABASE_DIALECT_UNSUPPORTED")
        self.engine = engine

    def provision_schema(self) -> None:
        # Called by an operator during a controlled migration, not on every
        # employee request or during an unauthorized application startup.
        metadata.create_all(self.engine, tables=[signed_cache_entries])

    def get(self, key: str) -> bytes | None:
        _validate(key)
        try:
            with self.engine.connect() as conn:
                row = conn.execute(select(
                    signed_cache_entries.c.value,
                    signed_cache_entries.c.expires_at,
                ).where(signed_cache_entries.c.cache_key == key)).first()
            if row is None:
                return None
            now = datetime.now(timezone.utc)
            expiry = row.expires_at
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry <= now:
                return None
            if not isinstance(row.value, bytes):
                raise CacheBackendError("CACHE_VALUE_INVALID")
            return row.value
        except CacheBackendError:
            raise
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc

    def set(self, key: str, value: bytes, ttl_seconds: int) -> None:
        _validate(key, value, ttl_seconds)
        expiry = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        dialect = self.engine.dialect.name
        insert = postgres_insert if dialect == "postgresql" else sqlite_insert
        try:
            stmt = insert(signed_cache_entries).values(
                cache_key=key, value=value, expires_at=expiry,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=[signed_cache_entries.c.cache_key],
                set_={"value": stmt.excluded.value, "expires_at": stmt.excluded.expires_at},
            )
            with self.engine.begin() as conn:
                conn.execute(stmt)
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc

    def delete(self, key: str) -> None:
        _validate(key)
        try:
            with self.engine.begin() as conn:
                conn.execute(delete(signed_cache_entries).where(
                    signed_cache_entries.c.cache_key == key,
                ))
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc

    def purge_expired(self, *, limit: int = 1000) -> int:
        """Bounded maintenance: delete expired entries from only our own table.

        An operator should schedule this separately. Runtime GET/SET requests
        must not unpredictably scan or delete an enterprise cache database.
        """
        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise CacheBackendError("CACHE_PURGE_LIMIT_INVALID")
        now = datetime.now(timezone.utc)
        try:
            with self.engine.begin() as conn:
                keys: list[str] = list(conn.scalars(
                    select(signed_cache_entries.c.cache_key)
                    .where(signed_cache_entries.c.expires_at <= now)
                    .order_by(signed_cache_entries.c.expires_at)
                    .limit(limit)
                ))
                if not keys:
                    return 0
                deleted = conn.execute(
                    delete(signed_cache_entries).where(
                        signed_cache_entries.c.cache_key.in_(keys),
                        signed_cache_entries.c.expires_at <= now,
                    ),
                )
                return int(deleted.rowcount or 0)
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc

    def ping(self) -> bool:
        try:
            # A healthy database connection is insufficient when an operator
            # has not provisioned the signed-cache table yet. Readiness must
            # verify the actual table is usable, without leaking row contents.
            with self.engine.connect() as conn:
                conn.execute(select(signed_cache_entries.c.cache_key).limit(1)).first()
            return True
        except Exception as exc:
            raise CacheBackendError("CACHE_BACKEND_UNAVAILABLE") from exc
