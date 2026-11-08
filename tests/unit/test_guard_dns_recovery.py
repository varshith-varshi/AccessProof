"""Guard self-heal restarts ONLY on the proven stale-DNS condition."""
from __future__ import annotations

import subprocess

import pytest

from scripts.certifier import guard_dns_recovery
from scripts.certifier.guard_dns_recovery import decide

STALE = {"ready": False, "policy_fresh": False, "sync_error": "ConnectError"}


def test_restarts_only_when_every_condition_holds():
    assert decide(STALE, container_dns=False, host_dns=True, is_busy=False, cooled=True) == "RESTART"


@pytest.mark.parametrize("kwargs,expected", [
    ({"container_dns": True, "host_dns": True, "is_busy": False, "cooled": True}, "NOT_DNS_REPORT_ONLY"),
    ({"container_dns": False, "host_dns": False, "is_busy": False, "cooled": True}, "NOT_DNS_REPORT_ONLY"),
    ({"container_dns": False, "host_dns": True, "is_busy": True, "cooled": True}, "DEFERRED_CERTIFICATION_RUNNING"),
    ({"container_dns": False, "host_dns": True, "is_busy": False, "cooled": False}, "DEFERRED_COOLDOWN"),
])
def test_never_restarts_otherwise(kwargs, expected):
    assert decide(STALE, **kwargs) == expected


@pytest.mark.parametrize("returncode,stdout,expected", [
    (0, "DNS_OK\n", True),
    (32, "DNS_FAILURE\n", False),
    (1, "Error: No such container", None),
    (32, "interpreter error", None),
    (0, "", None),
])
def test_docker_error_is_not_mistaken_for_stale_dns(monkeypatch, returncode, stdout, expected):
    def fake_run(argv, **_kwargs):
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")
    monkeypatch.setattr(guard_dns_recovery.subprocess, "run", fake_run)
    resolved = guard_dns_recovery.container_resolves("example-guard", "api.accessproof.in")
    assert resolved is expected
    if resolved is None:
        assert decide(STALE, container_dns=resolved, host_dns=True, is_busy=False,
                      cooled=True) == "NOT_DNS_REPORT_ONLY"


def test_docker_timeout_is_not_mistaken_for_stale_dns(monkeypatch):
    def timeout(argv, **_kwargs):
        raise subprocess.TimeoutExpired(argv, 20)
    monkeypatch.setattr(guard_dns_recovery.subprocess, "run", timeout)
    assert guard_dns_recovery.container_resolves("example-guard", "api.accessproof.in") is None


def test_non_transport_failures_and_healthy_guards_are_left_alone():
    assert decide({"ready": True}, container_dns=None, host_dns=True, is_busy=False, cooled=True) == "OK"
    for err in ("SOURCE_ACL_STALE", "HTTPStatusError", None):
        h = {"ready": False, "sync_error": err}
        assert decide(h, container_dns=False, host_dns=True, is_busy=False, cooled=True) == "NOT_READY_REPORT_ONLY"
    assert decide(None, container_dns=None, host_dns=True, is_busy=False, cooled=True) == "UNREACHABLE_REPORT_ONLY"
