"""Authorized synthetic cache-hit replay verifies exactly one return path."""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from scripts.customer_cache_route_probe import CacheRouteProbeError, _read_private, probe


def _config() -> dict[str, object]:
    return {
        "url": "http://127.0.0.1:7777/v1/protected-chat",
        "allowed_token": "synthetic-employee-allowed-01234",
        "denied_token": "synthetic-employee-denied-56789",
        "request_body": {"message": "synthetic-only approved question"},
        "allowed_canary": "SYNTHETIC_APPROVED_CANARY",
        "forbidden_canary": "SYNTHETIC_FORBIDDEN_CANARY",
        "cache_hit_field": "cache_hit",
    }


def test_approved_cache_warm_then_real_hit_then_denied_identity():
    calls: list[str] = []

    def handler(request: httpx.Request):
        calls.append(request.headers["authorization"])
        assert request.method == "POST"
        assert request.url.host == "127.0.0.1"
        assert request.url.path == "/v1/protected-chat"
        if request.headers["authorization"].endswith("allowed-01234"):
            return httpx.Response(200, json={
                "cache_hit": len(calls) > 1,
                "answer": "SYNTHETIC_APPROVED_CANARY",
            })
        return httpx.Response(403, json={"code": "CACHE_OUTPUT_NOT_AUTHORIZED"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = probe(_config(), client=client)
    assert result["status"] == "PASS_SINGLE_SYNTHETIC_CACHE_RETURN_ROUTE"
    assert result["certification_status"] == "NOT_CERTIFIED"
    assert [value["status"] for value in result["observations"]] == [200, 200, 403]
    assert len(calls) == 3
    assert "SYNTHETIC_APPROVED_CANARY" not in json.dumps(result)
    assert all("token" not in json.dumps(observation) for observation in result["observations"])


def test_does_not_pass_without_real_cache_hit():
    def handler(_: httpx.Request):
        return httpx.Response(200, json={"cache_hit": False, "answer": "SYNTHETIC_APPROVED_CANARY"})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(CacheRouteProbeError, match="CACHE_HIT_NOT_OBSERVED"):
            probe(_config(), client=client)


def test_detects_cross_employee_cached_answer_leak():
    calls = 0
    def handler(_: httpx.Request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"cache_hit": calls > 1, "answer": "SYNTHETIC_APPROVED_CANARY"})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(CacheRouteProbeError, match="UNEXPECTED_HTTP_RESULT_DENIED_HIT"):
            probe(_config(), client=client)


def test_forbidden_canary_anywhere_in_approved_or_denied_response_is_failure():
    def handler(_: httpx.Request):
        return httpx.Response(200, content=r'{"answer":"\u0053YNTHETIC_FORBIDDEN_CANARY"}')
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(CacheRouteProbeError, match="FORBIDDEN_CONTENT_RELEASED"):
            probe(_config(), client=client)


@pytest.mark.parametrize("url", [
    "https://api.example.com/v1/chat",
    "http://example.com/v1/chat",
    "http://169.254.169.254/latest/meta-data",
    "http://127.0.0.1:7777/",
    "http://user:pass@127.0.0.1:7777/v1/chat",
    "http://127.0.0.1:7777/v1/chat?unsafe=true",
])
def test_refuses_non_loopback_or_ambiguous_routes(url):
    config = _config()
    config["url"] = url
    with pytest.raises(CacheRouteProbeError, match="LOOPBACK_URL_REQUIRED"):
        probe(config)


def test_private_config_must_restrict_permissions(tmp_path: Path):
    path = tmp_path / "probe.json"
    path.write_text(json.dumps(_config()))
    path.chmod(0o644)
    with pytest.raises(CacheRouteProbeError, match="PERMISSIONS"):
        _read_private(path)
    path.chmod(0o600)
    assert _read_private(path)["url"] == _config()["url"]


def test_invalid_config_prevents_any_network_traffic():
    config = _config()
    del config["cache_hit_field"]
    with pytest.raises(CacheRouteProbeError, match="CONFIG_FIELDS_INVALID"):
        probe(config)
