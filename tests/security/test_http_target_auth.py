import base64
import socket

import httpx
import pytest

from packages.connector_sdk.http_target import (
    GenericHttpTarget,
    HttpTargetConfig,
    validate_cloud_url,
)
from packages.domain.models import Principal


def _public_dns(monkeypatch):
    def fake_getaddrinfo(host, port, type=0, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


def test_cloud_validation_rejects_non_global_cgnat(monkeypatch):
    def fake_getaddrinfo(host, port, type=0, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("100.64.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ValueError, match="Non-global"):
        validate_cloud_url("https://example.com/chat")


@pytest.mark.asyncio
async def test_cloud_probe_pins_validated_ip_and_preserves_host_and_sni(monkeypatch):
    _public_dns(monkeypatch)
    seen = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["host"] = request.url.host
        seen["host_header"] = request.headers.get("host")
        seen["sni"] = request.extensions.get("sni_hostname")
        return httpx.Response(200, json={"answer": "ok"})

    target = GenericHttpTarget(HttpTargetConfig(url="https://ai.example.com/chat"))
    await target._client.aclose()
    target._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
    result = await target.probe(principal=Principal("alice"), prompt="hello")
    await target._client.aclose()

    assert result.available is True
    assert seen["host"] == "8.8.8.8"
    assert seen["host_header"] == "ai.example.com"
    assert seen["sni"] == "ai.example.com"


@pytest.mark.asyncio
async def test_oauth_client_credentials_uses_basic_auth_and_bearer_for_target(monkeypatch):
    _public_dns(monkeypatch)
    calls = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(
            (request.url.path, request.headers.get("authorization"), request.headers.get("host"))
        )
        if request.url.path == "/token":
            return httpx.Response(200, json={"access_token": "oauth-token", "expires_in": 300})
        return httpx.Response(200, json={"answer": "ok"})

    target = GenericHttpTarget(
        HttpTargetConfig(
            url="https://ai.example.com/chat",
            oauth_token_url="https://auth.example.com/token",
            oauth_client_id="client-id",
            oauth_client_secret="client-secret",
            oauth_scope="rag.read",
        )
    )
    await target._client.aclose()
    target._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
    result = await target.probe(principal=Principal("alice"), prompt="hello")
    await target._client.aclose()

    expected_basic = "Basic " + base64.b64encode(b"client-id:client-secret").decode("ascii")
    assert result.available is True
    assert calls[0][0] == "/token" and calls[0][1] == expected_basic
    assert calls[1][0] == "/chat" and calls[1][1] == "Bearer oauth-token"


@pytest.mark.asyncio
async def test_basic_auth_supported_in_private_runner_mode():
    seen = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={"answer": "ok"})

    target = GenericHttpTarget(
        HttpTargetConfig(
            url="http://internal-rag.local/chat",
            runner_mode=True,
            basic_username="alice",
            basic_password="secret",
        )
    )
    await target._client.aclose()
    target._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
    result = await target.probe(principal=Principal("alice"), prompt="hello")
    await target._client.aclose()
    assert result.available is True
    assert seen["authorization"] == "Basic " + base64.b64encode(b"alice:secret").decode("ascii")


def test_cloud_mode_rejects_mtls_file_configuration(monkeypatch):
    _public_dns(monkeypatch)
    with pytest.raises(ValueError, match="mTLS"):
        GenericHttpTarget(
            HttpTargetConfig(url="https://ai.example.com/chat", mtls_cert_file="/tmp/client.pem")
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,payload",
    [
        (302, {"answer": ""}),
        (204, None),
        (200, {}),
        (200, []),
        (200, {"answer": "denied", "citations": "secret"}),
        (200, {"answer": "denied", "tool_outputs": [{}]}),
    ],
)
async def test_malformed_and_redirect_responses_never_prove_denial(status, payload):
    target = GenericHttpTarget(HttpTargetConfig(url="http://internal/chat", runner_mode=True))
    await target._client.aclose()
    target._client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(status, json=payload))
    )
    try:
        observed = await target.probe(principal=Principal("alice"), prompt="probe")
        assert observed.available is False
    finally:
        await target._client.aclose()


@pytest.mark.asyncio
async def test_get_probe_uses_query_parameters():
    def handler(request):
        assert request.url.params["message"] == "hello"
        assert not request.content
        return httpx.Response(200, json={"answer": "denied"})

    target = GenericHttpTarget(
        HttpTargetConfig(url="http://internal/chat", runner_mode=True, method="GET")
    )
    await target._client.aclose()
    target._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        assert (await target.probe(principal=Principal("alice"), prompt="hello")).available
    finally:
        await target._client.aclose()
