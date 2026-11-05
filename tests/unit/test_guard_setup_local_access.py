"""The Guard setup page opens for the host browser and nobody else."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from apps.guard.accessproof_guard import app as guard

GATEWAY = "172.17.0.1"


def request(peer: str, host: str = "127.0.0.1") -> SimpleNamespace:
    return SimpleNamespace(url=SimpleNamespace(hostname=host), client=SimpleNamespace(host=peer))


@pytest.fixture
def docker_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guard, "_docker_gateway", lambda: GATEWAY)
    monkeypatch.setenv("ACCESSPROOF_GUARD_SETUP_TRUST_DOCKER_GATEWAY", "1")


def test_loopback_peer_is_allowed() -> None:
    guard._require_local_setup(request("127.0.0.1"))


def test_docker_gateway_is_allowed_when_packaged_guard_opts_in(docker_host: None) -> None:
    guard._require_local_setup(request(GATEWAY))


def test_docker_gateway_is_refused_without_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guard, "_docker_gateway", lambda: GATEWAY)
    monkeypatch.delenv("ACCESSPROOF_GUARD_SETUP_TRUST_DOCKER_GATEWAY", raising=False)
    with pytest.raises(HTTPException):
        guard._require_local_setup(request(GATEWAY))


@pytest.mark.parametrize("peer", ["172.17.0.5", "10.0.0.8", "203.0.113.9", "unknown"])
def test_sibling_container_or_remote_peer_is_refused(docker_host: None, peer: str) -> None:
    with pytest.raises(HTTPException):
        guard._require_local_setup(request(peer))


def test_foreign_host_header_is_refused_from_the_gateway(docker_host: None) -> None:
    with pytest.raises(HTTPException):
        guard._require_local_setup(request(GATEWAY, host="evil.example"))


def test_gateway_is_read_from_the_route_table(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    routes = tmp_path / "route"
    routes.write_text(
        "Iface Destination Gateway Flags\n"
        "eth0 000011AC 00000000 0001\n"
        "eth0 00000000 010011AC 0003\n"
    )
    real_path = guard.Path
    monkeypatch.setattr(guard, "Path", lambda value: routes if value == "/proc/net/route" else real_path(value))
    assert guard._docker_gateway() == GATEWAY
