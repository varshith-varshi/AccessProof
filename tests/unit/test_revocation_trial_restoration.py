"""Recovery must be tenant-bound, retried on transport failure and idempotent."""
from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from scripts.live import revocation_trial as rt


def _trial(grant, invite):
    trial = rt.Trial.__new__(rt.Trial)
    trial.alice_oid = "synthetic-alice"
    trial.lab = SimpleNamespace(invite=invite, strip_site_groups=lambda _: None)
    trial._grant_on = lambda _: {"id": "restored"} if grant["present"] else None
    return trial


def _marker(monkeypatch, tmp_path, trial):
    path = tmp_path / "recovery.json"
    monkeypatch.setattr(rt, "RECOVERY", path)
    trial._record({"trial": "A", "kind": "direct", "item": "synthetic-file"})
    return path


def test_restore_retries_temporary_graph_dns_and_clears_marker(monkeypatch, tmp_path):
    grant = {"present": False}
    calls = []

    def invite(item, actor):
        calls.append((item, actor))
        if len(calls) < 3:
            raise httpx.ConnectError("temporary DNS failure")
        grant["present"] = True

    trial = _trial(grant, invite)
    marker = _marker(monkeypatch, tmp_path, trial)
    monkeypatch.setattr(rt.time, "sleep", lambda _: None)
    trial.restore()
    assert len(calls) == 3
    assert grant["present"]
    assert not marker.exists()


def test_restore_is_idempotent_when_grant_already_exists(monkeypatch, tmp_path):
    grant = {"present": True}

    def should_not_invite(*_):
        pytest.fail("restoration duplicated an existing SharePoint grant")

    trial = _trial(grant, should_not_invite)
    marker = _marker(monkeypatch, tmp_path, trial)
    trial.restore()
    assert not marker.exists()


def test_restore_rejects_other_organization_without_mutating(monkeypatch, tmp_path):
    trial = _trial({"present": False}, lambda *_: pytest.fail("wrong tenant mutated"))
    marker = _marker(monkeypatch, tmp_path, trial)
    import json
    record = json.loads(marker.read_text())
    record["organization_id"] = "different-tenant"
    marker.write_text(json.dumps(record))
    with pytest.raises(RuntimeError, match="RESTORE_SCOPE_MISMATCH"):
        trial.restore()
    assert marker.exists()


def test_restore_preserves_marker_on_permission_denial(monkeypatch, tmp_path):
    def deny(*_):
        response = httpx.Response(403, request=httpx.Request("POST", "https://graph.microsoft.com/"))
        raise httpx.HTTPStatusError("Forbidden", request=response.request, response=response)

    trial = _trial({"present": False}, deny)
    marker = _marker(monkeypatch, tmp_path, trial)
    with pytest.raises(httpx.HTTPStatusError):
        trial.restore()
    assert marker.exists()


def test_unreversible_recovery_is_not_silently_cleared(monkeypatch, tmp_path):
    trial = _trial({"present": False}, lambda *_: None)
    marker = tmp_path / "recovery.json"
    monkeypatch.setattr(rt, "RECOVERY", marker)
    trial._record({"trial": "D", "kind": "delete", "item": "synthetic-file"})
    with pytest.raises(RuntimeError, match="NOT_AUTOMATICALLY_REVERSIBLE"):
        trial.restore()
    assert marker.exists()
