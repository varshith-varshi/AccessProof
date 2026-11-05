"""Read-only AWS retry is narrow: no certificate import retries."""
from __future__ import annotations

import subprocess

import pytest

from scripts.certifier import ssm_ops


def _aws_error(message: str = "network timeout", code: int = 255):
    return subprocess.CalledProcessError(code, ["aws", "ssm"], stderr=message)


def test_read_only_retries_two_transient_cli_errors(monkeypatch):
    calls = []
    def fake_run(*args, **kwargs):
        calls.append(args)
        if len(calls) < 3:
            raise _aws_error()
        return "ready\n"
    delays = []
    monkeypatch.setattr(ssm_ops, "run", fake_run)
    monkeypatch.setattr(ssm_ops.time, "sleep", delays.append)
    assert ssm_ops.read_only("certificate_status", organizationId="fake") == "ready"
    assert len(calls) == 3 and delays == [1, 2]
    assert all(call[0] == ssm_ops.READ_ONLY for call in calls)


def test_read_only_never_retries_access_denied(monkeypatch):
    calls = []
    def denied(*args, **kwargs):
        calls.append(1)
        raise _aws_error("AccessDeniedException", 255)
    monkeypatch.setattr(ssm_ops, "run", denied)
    with pytest.raises(subprocess.CalledProcessError):
        ssm_ops.read_only("route_status")
    assert len(calls) == 1


def test_read_only_never_retries_arbitrary_non_255_errors(monkeypatch):
    calls = []
    def failed(*args, **kwargs):
        calls.append(1)
        raise _aws_error("invalid arguments", 2)
    monkeypatch.setattr(ssm_ops, "run", failed)
    with pytest.raises(subprocess.CalledProcessError):
        ssm_ops.read_only("route_status")
    assert len(calls) == 1


def test_import_operation_is_not_retry_wrapped(monkeypatch):
    calls = []
    def failed(*args, **kwargs):
        calls.append(args)
        raise _aws_error()
    monkeypatch.setattr(ssm_ops, "run", failed)
    with pytest.raises(subprocess.CalledProcessError):
        ssm_ops.import_payload("source_certificate_import", {"synthetic": True})
    assert len(calls) == 1
