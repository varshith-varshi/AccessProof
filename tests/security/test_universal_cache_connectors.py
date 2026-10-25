"""Security and interoperability contract for supported cache backends."""
from __future__ import annotations

import time
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine

from packages.rag_sdk import (
    CachedAnswerManifestSigner, CachedAnswerManifestVerifier,
    SourceAttestationSigner, SourceAttestationVerifier,
    ContentBinding, RetrievedResource,
)
from packages.rag_sdk.cache_backends import (
    CallbackBackend, CacheBackendError, MemoryBackend, MemcachedBackend,
    RedisBackend, SQLAlchemyBackend,
)
from packages.demo_cache.universal import SignedBackendAnswerCache
from packages.demo_cache.factory import configured_cache_backend, CacheConfigurationError


class FakeRedis:
    def __init__(self):
        self.data: dict[str, bytes] = {}
        self.fail = False
    def get(self, key):
        if self.fail:
            raise TimeoutError("synthetic redis outage")
        return self.data.get(key)
    def setex(self, key, ttl, value):
        self.data[key] = value
        return True
    def delete(self, key):
        self.data.pop(key, None)
    def ping(self):
        if self.fail:
            raise TimeoutError("synthetic redis outage")
        return True


class FakeMemcached:
    def __init__(self):
        self.data = {}
        self.fail = False
    def get(self, key):
        if self.fail:
            raise TimeoutError("synthetic memcached outage")
        return self.data.get(key)
    def set(self, key, value, *, expire, noreply):
        assert 0 < expire <= 3600 and noreply is False
        self.data[key] = value
        return True
    def delete(self, key, *, noreply):
        assert noreply is False
        self.data.pop(key, None)
    def version(self):
        if self.fail:
            raise TimeoutError("synthetic memcached outage")
        return b"1.6.0"


class FakeGuard:
    def __init__(self):
        self.allowed = True
        self.calls = []
    def filter_resources(self, **kwargs):
        self.calls.append(("layer1", kwargs["employee_token"]))
        resources = kwargs["resources"]
        return {
            "decision": "allow" if self.allowed else "block",
            "mode": "protect", "decision_id": "g1",
            "allowed": ([{
                "source_id": item.source_id, "resource_id": item.resource_id,
                "chunk_ids": [item.chunk_id] if item.chunk_id else [],
            } for item in resources] if self.allowed else []),
        }
    def check_output(self, **kwargs):
        self.calls.append(("layer2", kwargs["employee_token"]))
        return {"decision": "allow", "reason": "OK"}


@pytest.fixture(params=["redis", "memcached", "memory", "callbacks", "sqlite"])
def backend(request, tmp_path):
    key = request.param
    if key == "redis":
        return RedisBackend(FakeRedis())
    if key == "memcached":
        return MemcachedBackend(FakeMemcached())
    if key == "memory":
        return MemoryBackend()
    if key == "callbacks":
        values = MemoryBackend()
        return CallbackBackend(read=values.get, write=values.set,
                               remove=values.delete, health=values.ping)
    if key == "sqlite":
        engine = create_engine(f"sqlite:///{tmp_path / 'answer_cache.sqlite'}")
        result = SQLAlchemyBackend(engine)
        result.provision_schema()
        return result
    raise AssertionError(key)


def _data():
    source_private = Ed25519PrivateKey.generate()
    cache_private = Ed25519PrivateKey.generate()
    item = RetrievedResource(
        source_id="source-a", resource_id="file-A", chunk_id="chunk-0",
        content="Confidential synthetic information", content_version="v1",
    )
    token = SourceAttestationSigner(
        key_id="source-key", private_key=source_private,
    ).issue(ContentBinding(
        "tenant-A", "app-A", item.source_id, item.resource_id, item.chunk_id,
        item.content_version, item.content,
    ))
    item = replace(item, content_attestation=token)
    return item, source_private, cache_private


def _cache(backend, item, source_key, cache_key, *, tenant="tenant-A", app="app-A"):
    return SignedBackendAnswerCache(
        backend=backend, tenant_id=tenant, application_id=app,
        signer=CachedAnswerManifestSigner(key_id="cache-key", private_key=cache_key),
        verifier=CachedAnswerManifestVerifier(
            tenant_id=tenant, trusted_keys={"cache-key": cache_key.public_key()},
        ),
        source_verifier=SourceAttestationVerifier(
            tenant_id=tenant, trusted_keys={"source-key": source_key.public_key()},
        ),
    )


def test_every_backend_allows_then_freshly_denies_cached_response(backend):
    item, source_key, cache_key = _data()
    cache = _cache(backend, item, source_key, cache_key)
    cache.store("important question", "financial result", [item])
    guard = FakeGuard()
    allow = cache.authorize_hit(
        question="important question", employee_token="employee-a", guard=guard,
    )
    assert allow is not None and allow.decision == "allow"
    assert allow.answer == "financial result"
    assert allow.citations == ("file-A",)
    assert guard.calls == [("layer1", "employee-a"), ("layer2", "employee-a")]
    guard.allowed = False
    block = cache.authorize_hit(
        question="important question", employee_token="employee-a", guard=guard,
    )
    assert block is not None and block.decision == "block" and block.answer is None
    assert guard.calls[-1] == ("layer1", "employee-a")
    assert cache.authorize_hit(question="not cached", employee_token="employee-a",
                               guard=guard) is None
    cache.invalidate("important question")
    assert cache.authorize_hit(question="important question",
                               employee_token="employee-a", guard=guard) is None


def test_every_backend_refuses_signature_tampering(backend):
    item, source_key, cache_key = _data()
    cache = _cache(backend, item, source_key, cache_key)
    cache.store("q", "signed answer", [item])
    key = cache._key("q")
    raw = backend.get(key)
    assert raw is not None
    backend.set(key, raw.replace(b"signed answer", b"forged answer"), 300)
    result = cache.authorize_hit(question="q", employee_token="employee", guard=FakeGuard())
    assert result is not None and result.decision == "block" and result.answer is None


def test_every_backend_is_app_and_tenant_scoped(backend):
    item, source_key, cache_key = _data()
    owner = _cache(backend, item, source_key, cache_key)
    owner.store("common question", "financial result", [item])
    foreign_app = _cache(backend, item, source_key, cache_key, app="app-B")
    foreign_tenant = _cache(backend, item, source_key, cache_key, tenant="tenant-B")
    assert foreign_app.authorize_hit(
        question="common question", employee_token="user", guard=FakeGuard(),
    ) is None
    assert foreign_tenant.authorize_hit(
        question="common question", employee_token="user", guard=FakeGuard(),
    ) is None


def test_backend_unavailability_never_authorizes_stale_answer():
    item, source_key, cache_key = _data()
    fake = FakeMemcached()
    cache = _cache(MemcachedBackend(fake), item, source_key, cache_key)
    cache.store("q", "private", [item])
    fake.fail = True
    response = cache.authorize_hit(question="q", employee_token="employee", guard=FakeGuard())
    assert response is not None and response.decision == "block" and response.answer is None


def test_inmemory_respects_ttl(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    backend = MemoryBackend()
    backend.set("key", b"payload", 1)
    clock[0] = 100.5
    assert backend.get("key") == b"payload"
    clock[0] = 101.1
    assert backend.get("key") is None


def test_sqlite_backend_does_not_create_schema_implicitly(tmp_path):
    backend = SQLAlchemyBackend(create_engine(f"sqlite:///{tmp_path / 'unprovisioned.sqlite'}"))
    with pytest.raises(CacheBackendError, match="CACHE_BACKEND_UNAVAILABLE"):
        backend.get("known-key")
    with pytest.raises(CacheBackendError, match="CACHE_BACKEND_UNAVAILABLE"):
        backend.ping()
    backend.provision_schema()
    assert backend.ping()
    backend.set("known-key", b"payload", 1)
    assert backend.get("known-key") == b"payload"
    backend.delete("known-key")
    assert backend.get("known-key") is None


def test_factory_fails_closed_on_bad_backend_config():
    for config in (
        {"ACCESSPROOF_DEMO_CACHE_BACKEND": "memcached"},
        {"ACCESSPROOF_DEMO_CACHE_BACKEND": "postgresql",
         "ACCESSPROOF_DEMO_CACHE_SQLALCHEMY_URL": "sqlite:///wrong"},
        {"ACCESSPROOF_DEMO_CACHE_BACKEND": "memory", "ACCESSPROOF_ENV": "production"},
        {"ACCESSPROOF_DEMO_CACHE_BACKEND": "arbitrary"},
    ):
        with pytest.raises(CacheConfigurationError):
            configured_cache_backend(config)
    assert configured_cache_backend({}) is None


def test_memcached_bad_write_is_failed_not_silently_accepted():
    class BadWrite(FakeMemcached):
        def set(self, *args, **kwargs):
            return False
    with pytest.raises(CacheBackendError, match="CACHE_WRITE_FAILED"):
        MemcachedBackend(BadWrite()).set("key", b"value", 30)


def test_many_signed_source_dependencies_are_authorized_not_truncated():
    backend = MemoryBackend()
    source_key, cache_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    signer = SourceAttestationSigner(key_id="source-key", private_key=source_key)
    verified = []
    for index in range(50):
        source = ContentBinding(
            "tenant-A", "app-A", "source-a", f"doc-{index}",
            f"chunk-{index}", "1", f"approved chunk {index}",
        )
        verified.append(RetrievedResource(
            source_id=source.source_id, resource_id=source.resource_id,
            chunk_id=source.chunk_id, content_version=source.content_version,
            content=source.content, content_attestation=signer.issue(source),
        ))
    cache = SignedBackendAnswerCache(
        backend=backend, tenant_id="tenant-A", application_id="app-A",
        signer=CachedAnswerManifestSigner(key_id="cache-key", private_key=cache_key),
        verifier=CachedAnswerManifestVerifier(
            tenant_id="tenant-A", trusted_keys={"cache-key": cache_key.public_key()},
        ),
        source_verifier=SourceAttestationVerifier(
            tenant_id="tenant-A", trusted_keys={"source-key": source_key.public_key()},
        ),
    )
    cache.store("fifty dependencies", "approved combined answer", verified)
    guard = FakeGuard()
    answer = cache.authorize_hit(question="fifty dependencies",
                                 employee_token="employee", guard=guard)
    assert answer is not None and answer.decision == "allow"
    assert len(answer.citations) == 50
    guard.allowed = False
    denied = cache.authorize_hit(question="fifty dependencies",
                                 employee_token="employee", guard=guard)
    assert denied is not None and denied.decision == "block"



def test_factory_detects_selected_backend_and_rejects_conflicts():
    from packages.rag_sdk.cache_backends import RedisBackend, MemcachedBackend
    redis = configured_cache_backend({
        "ACCESSPROOF_DEMO_CACHE_URL": "redis://127.0.0.1:6379/0",
    })
    assert isinstance(redis, RedisBackend)
    memcached = configured_cache_backend({
        "ACCESSPROOF_DEMO_CACHE_MEMCACHED_HOST": "memcached.internal",
        "ACCESSPROOF_DEMO_CACHE_MEMCACHED_PORT": "11211",
    })
    assert isinstance(memcached, MemcachedBackend)
    with pytest.raises(CacheConfigurationError, match="CACHE_BACKEND_AMBIGUOUS"):
        configured_cache_backend({
            "ACCESSPROOF_DEMO_CACHE_URL": "redis://localhost:6379",
            "ACCESSPROOF_DEMO_CACHE_MEMCACHED_HOST": "memcached.internal",
        })
    with pytest.raises(CacheConfigurationError, match="CACHE_MULTIPLE_BACKENDS_CONFIGURED"):
        configured_cache_backend({
            "ACCESSPROOF_DEMO_CACHE_BACKEND": "redis",
            "ACCESSPROOF_DEMO_CACHE_URL": "redis://localhost:6379",
            "ACCESSPROOF_DEMO_CACHE_MEMCACHED_HOST": "memcached.internal",
        })


def test_memcached_factory_reuses_thread_safe_connection_pool():
    from packages.demo_cache.factory import configured_cache_backend
    config = {
        "ACCESSPROOF_DEMO_CACHE_BACKEND": "memcached",
        "ACCESSPROOF_DEMO_CACHE_MEMCACHED_HOST": "memcache.service.local",
    }
    first, second = configured_cache_backend(config), configured_cache_backend(config)
    assert first is second
    assert first.client.__class__.__name__ == "PooledClient"



def test_sql_cache_expired_rows_are_boundedly_purged(tmp_path):
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import update
    from packages.rag_sdk.cache_backends import signed_cache_entries
    engine = create_engine(f"sqlite:///{tmp_path / 'cache_cleanup.sqlite'}")
    backend = SQLAlchemyBackend(engine)
    backend.provision_schema()
    backend.set("expired-a", b"old-a", 300)
    backend.set("expired-b", b"old-b", 300)
    backend.set("current-c", b"new-c", 300)
    with engine.begin() as conn:
        conn.execute(
            update(signed_cache_entries)
            .where(signed_cache_entries.c.cache_key.in_(["expired-a", "expired-b"]))
            .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=60))
        )
    assert backend.purge_expired(limit=1) == 1
    assert backend.purge_expired(limit=1) == 1
    assert backend.purge_expired(limit=1) == 0
    assert backend.get("current-c") == b"new-c"
    with pytest.raises(CacheBackendError, match="CACHE_PURGE_LIMIT_INVALID"):
        backend.purge_expired(limit=0)
