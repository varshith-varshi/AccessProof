"""Scale: the Guard re-downloads verified identity mappings only when they
change, never trusts a stale set for longer than the forced-refresh bound,
and older Guards keep receiving the full set."""
from __future__ import annotations

import httpx
import pytest

from apps.guard.accessproof_guard.cache import PolicyCache
from apps.guard.accessproof_guard.sync import GuardMachineCredentials, GuardSyncClient

ISS = "https://login.microsoftonline.com/6479e7ca-b256-4ebc-a408-871b9046547c/v2.0"
T = "6479e7ca-b256-4ebc-a408-871b9046547c"


def _envelope(version="idv-1", mappings=None, unchanged=False):
    body = {"kind": "full", "version": 1,
            "decisions": [{"version": 1, "subject_id": "alice-oid", "source_id": "sp", "resource_id": "doc",
                           "scope": "read", "decision": "allow"}],
            "applications": [{"application_id": "rag", "source_id": "sp", "mode": "protect", "source_acl_healthy": True}],
            "authorization_revisions": [{"application_id": "rag", "revision": 1, "revision_hash": "1" * 64,
                                         "generated_at": "2026-11-03T00:00:00Z"}],
            "identity_version": version}
    if unchanged:
        body["identity_mappings_unchanged"] = True
    else:
        body["identity_mappings"] = mappings if mappings is not None else [
            {"source_id": "sp", "issuer": ISS, "subject": "alice-oid", "tenant_id": T, "source_subject_id": "alice-oid"}]
    return body


class _Steps:
    """One envelope per sync step; a step may serve several GETs (full refetch)."""

    def __init__(self, envelopes):
        self.envelopes, self.step = envelopes, 0

    def advance(self):
        self.step += 1


def _client(cache, responses, seen):
    steps = _Steps(responses)

    def handler(req):
        if req.method == "GET":
            seen.append(dict(req.url.params))
            return httpx.Response(200, json=steps.envelopes[min(steps.step, len(steps.envelopes) - 1)])
        return httpx.Response(200, json={"ok": True})
    client = GuardSyncClient(cache, GuardMachineCredentials("https://control.example", "guard", "machine", "1"),
                             httpx.Client(transport=httpx.MockTransport(handler)))
    original = client.sync_once

    def sync_once_step():
        try:
            return original()
        finally:
            steps.advance()
    client.sync_once = sync_once_step
    return client


def test_unchanged_keeps_installed_set_and_offers_version(tmp_path):
    cache = PolicyCache(str(tmp_path / "g.db"))
    seen: list[dict] = []
    client = _client(cache, [_envelope(), _envelope(unchanged=True)], seen)
    client.sync_once()
    assert all("identity_version" not in p for p in seen)        # first sync: full set
    assert cache.resolve_identity("sp", ISS, "alice-oid", T) == "alice-oid"
    n = len(seen)
    client.sync_once()
    assert seen[n]["identity_version"] == "idv-1"               # offered on the next sync
    assert cache.resolve_identity("sp", ISS, "alice-oid", T) == "alice-oid"   # kept


def test_changed_set_replaces_and_revocation_takes_effect(tmp_path):
    cache = PolicyCache(str(tmp_path / "g.db"))
    client = _client(cache, [_envelope(), _envelope(version="idv-2", mappings=[])], [])
    client.sync_once()
    client.sync_once()
    assert cache.resolve_identity("sp", ISS, "alice-oid", T) is None


def test_unchanged_for_a_different_version_fails_closed(tmp_path):
    cache = PolicyCache(str(tmp_path / "g.db"))
    client = _client(cache, [_envelope(), _envelope(version="idv-OTHER", unchanged=True)], [])
    client.sync_once()
    assert cache.resolve_identity("sp", ISS, "alice-oid", T) == "alice-oid"
    client.sync_once()
    # Not a confirmation of what this Guard holds: treated as an empty set
    # (existing rule for a missing envelope) -> every identity is denied.
    assert cache.resolve_identity("sp", ISS, "alice-oid", T) is None


def test_forced_full_refresh_after_bound(tmp_path, monkeypatch):
    cache = PolicyCache(str(tmp_path / "g.db"))
    seen: list[dict] = []
    client = _client(cache, [_envelope(), _envelope()], seen)
    client.sync_once()
    import apps.guard.accessproof_guard.cache as cache_module
    real = cache_module.time.time
    monkeypatch.setattr(cache_module.time, "time", lambda: real() + PolicyCache.IDENTITY_FULL_REFRESH_SECONDS + 1)
    assert cache.reusable_identity_version() is None
    n = len(seen)
    client.sync_once()
    assert "identity_version" not in seen[n]


def test_restart_does_not_trust_a_stale_identity_version(tmp_path, monkeypatch):
    path = str(tmp_path / "g.db")
    PolicyCache(path).apply_sync_snapshot(1, [], full_snapshot=True, applications=[], mappings=[],
                                          revisions=None, identity_version="idv-1")
    assert PolicyCache(path).reusable_identity_version() == "idv-1"
    import apps.guard.accessproof_guard.cache as cache_module
    real = cache_module.time.time
    monkeypatch.setattr(cache_module.time, "time", lambda: real() + 10_000)
    assert PolicyCache(path).reusable_identity_version() is None
