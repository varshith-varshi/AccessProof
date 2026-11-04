"""Cached-chunk freshness: a still-valid attestation of an OLD document version
must not be accepted once the provider reports a newer version.

Covers document update, unknown/deleted documents, the signed answer cache
(dependency versions), Guard sync semantics and the control plane's
completeness rule. Existing signed-cache and revision-binding behaviour is
unchanged for sources without delivered versions (all other suites).
"""
from __future__ import annotations

import json

from apps.guard.accessproof_guard.cache import PolicyCache
from apps.guard.accessproof_guard.sync import GuardSyncClient
from tests.security.test_gateway_all_response_routes import (
    _answer_body, _assert_denial, _cached_body, _gateway,
)
from tests.security.test_multisource_guard_v2 import DOC, SHAREPOINT, _token

ALICE = {"Authorization": "Bearer " + _token("alice")}


def _versions(policy: PolicyCache, items: dict[str, list[str]], sources=(SHAREPOINT,)) -> None:
    with policy._lock, policy._write_transaction():
        policy.set_resource_versions({"sources": list(sources), "items": [
            {"source_id": SHAREPOINT, "resource_id": rid, "versions": v} for rid, v in items.items()]}, "d1")


def test_current_version_is_released(tmp_path, monkeypatch):
    gateway, policy, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    _versions(policy, {DOC: ["etag1"]})
    with gateway:
        assert gateway.post("/v1/chat/completions", headers=ALICE, json=_answer_body(chunk, stream=False)).status_code == 200
    assert observed["llm_count"] == 1


def test_document_update_refuses_cached_chunk_of_previous_version(tmp_path, monkeypatch):
    """The cached chunk's attestation (etag1) is still valid; the document is now etag2."""
    gateway, policy, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    _versions(policy, {DOC: ["etag2", "ctag2"]})
    with gateway:
        _assert_denial(gateway.post("/v1/chat/completions", headers=ALICE, json=_answer_body(chunk, stream=False)))
    assert observed["llm_count"] == 0


def test_deleted_or_unknown_document_in_versioned_source_is_refused(tmp_path, monkeypatch):
    gateway, policy, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    _versions(policy, {"some-other-document": ["etag9"]})
    with gateway:
        _assert_denial(gateway.post("/v1/chat/completions", headers=ALICE, json=_answer_body(chunk, stream=False)))
    assert observed["llm_count"] == 0


def test_signed_cached_answer_built_from_previous_version_is_refused(tmp_path, monkeypatch):
    gateway, policy, observed, _chunk, cached, signature, *_ = _gateway(tmp_path, monkeypatch)
    with gateway:
        assert gateway.post("/v1/cache/authorize", headers=ALICE, json=_cached_body(cached, signature)).status_code == 200
        _versions(policy, {DOC: ["etag2"]})
        _assert_denial(gateway.post("/v1/cache/authorize", headers=ALICE, json=_cached_body(cached, signature)))
    assert observed["llm_count"] == 0


def test_cache_refusal_reasons(tmp_path):
    cache = PolicyCache(str(tmp_path / "g.db"))
    assert cache.content_version_refusal(SHAREPOINT, DOC, ["etag1"]) is None          # unversioned: legacy
    _versions(cache, {DOC: ["etag2", "ctag2"]})
    assert cache.content_version_refusal(SHAREPOINT, DOC, ["etag2"]) is None
    assert cache.content_version_refusal(SHAREPOINT, DOC, ["ctag2"]) is None
    assert cache.content_version_refusal(SHAREPOINT, DOC, ["etag1"]) == "SOURCE_CONTENT_VERSION_STALE"
    assert cache.content_version_refusal(SHAREPOINT, DOC, ["etag2", "etag1"]) == "SOURCE_CONTENT_VERSION_STALE"
    assert cache.content_version_refusal(SHAREPOINT, DOC, [None]) == "SOURCE_CONTENT_VERSION_REQUIRED"
    assert cache.content_version_refusal(SHAREPOINT, "gone", ["etag2"]) == "SOURCE_CONTENT_VERSION_UNKNOWN"
    assert cache.content_version_refusal("another-source", DOC, ["old"]) is None


def test_sync_keeps_on_unchanged_and_drops_when_control_plane_sends_none():
    keep = GuardSyncClient._resource_versions({"resource_versions_unchanged": True, "resource_versions_digest": "d1",
                                                 "_versions_digest_sent": "d1"})
    assert keep is False
    # "unchanged" for a digest this Guard did not send is not trusted.
    assert GuardSyncClient._resource_versions({"resource_versions_unchanged": True, "resource_versions_digest": "d2",
                                                 "_versions_digest_sent": "d1"}) is None
    assert GuardSyncClient._resource_versions({}) is None
    full = {"sources": [SHAREPOINT], "items": []}
    assert GuardSyncClient._resource_versions({"resource_versions": full}) == full


def test_validate_rejects_items_outside_listed_sources(tmp_path):
    cache = PolicyCache(str(tmp_path / "g.db"))
    for bad in ({"sources": [SHAREPOINT], "items": [{"source_id": "x", "resource_id": DOC, "versions": ["v"]}]},
                {"sources": [SHAREPOINT], "items": [{"source_id": SHAREPOINT, "resource_id": DOC, "versions": []}]},
                {"sources": "nope", "items": []}):
        try:
            cache.validate_resource_versions(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted {bad}")


def test_control_plane_versions_only_complete_sources():
    from apps.api.accessproof_api.content_versions import needs_backfill, resource_versions_envelope
    from apps.api.accessproof_api.db import (
        Base, GuardResource, Organization, Project, SessionLocal, SourceConnection, engine,
    )
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        org = Organization(name="v")
        db.add(org)
        db.flush()
        project = Project(organization_id=org.id, name="p")
        db.add(project)
        db.flush()
        src = SourceConnection(organization_id=org.id, project_id=project.id, provider="sharepoint", boundary="root", name="s")
        db.add(src)
        db.flush()
        db.add_all([
            GuardResource(organization_id=org.id, source_id=src.id, provider_resource_id="a", resource_type="document",
                          metadata_json=json.dumps({"eTag": "e1", "cTag": "c1"})),
            GuardResource(organization_id=org.id, source_id=src.id, provider_resource_id="gone", resource_type="document",
                          metadata_json=json.dumps({"deleted": True})),
            GuardResource(organization_id=org.id, source_id=src.id, provider_resource_id="root", resource_type="folder"),
        ])
        db.flush()
        env = resource_versions_envelope(db, org.id, [src.id])
        assert env["sources"] == [src.id] and env["items"] == [{"source_id": src.id, "resource_id": "a", "versions": ["c1", "e1"]}]
        assert not needs_backfill(db, src)
        db.add(GuardResource(organization_id=org.id, source_id=src.id, provider_resource_id="b", resource_type="document",
                             metadata_json="{}"))
        db.flush()
        partial = resource_versions_envelope(db, org.id, [src.id])
        assert partial["sources"] == [] and partial["items"] == []          # never partially versioned
        assert needs_backfill(db, src)
        assert partial["digest"] != env["digest"]
