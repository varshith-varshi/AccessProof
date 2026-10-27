"""Adversarial checks for the customer-visible local HTTP route probe."""
from __future__ import annotations

import json

import httpx
import pytest

from customer_simulation.route_probe import (
    RouteProbeConfig, RouteProbeError, probe_local_customer_routes,
)


CONFIG = RouteProbeConfig(
    base_url="http://127.0.0.1:45555",
    authorized_token="auth-good",
    denied_token="auth-denied",
    allowed_canary="PUBLIC_TEST_CONTENT",
    forbidden_canary="PRIVATE_TEST_SECRET",
    invalid_token="invalid-token",
)


def _fake_client(*, leak: str | None = None, bad_sse: bool = False, redirect: bool = False):
    def respond(request: httpx.Request) -> httpx.Response:
        if redirect:
            return httpx.Response(302, headers={"Location": "https://untrusted.invalid/"})
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        stream = request.url.path.endswith("/stream")
        if token == "invalid-token":
            return httpx.Response(401, json={"detail": "UNAUTHORIZED"})
        authorized = token == "auth-good"
        message = "PUBLIC_TEST_CONTENT" if authorized else "Access denied"
        if leak == "private" and not authorized:
            message += " PRIVATE_TEST_SECRET"
        if leak == "public" and not authorized:
            message += " PUBLIC_TEST_CONTENT"
        if leak == "private_in_positive" and authorized:
            message += " PRIVATE_TEST_SECRET"
        if stream:
            body = f"event: token\ndata: {json.dumps(message)}\n\n"
            if not bad_sse:
                body += "event: complete\ndata: {}\n\n"
            return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})
        return httpx.Response(200, json={"answer": message, "citations": []})

    return httpx.Client(base_url=CONFIG.base_url, transport=httpx.MockTransport(respond))


def test_probe_passes_only_explicit_json_and_sse_customer_routes() -> None:
    with _fake_client() as client:
        result = probe_local_customer_routes(CONFIG, client=client)
    assert result["production_certification"] is False
    assert result["synthetic_only"] is True
    assert len(result["checks"]) == 6


@pytest.mark.parametrize("leak", ["private", "public", "private_in_positive"])
def test_probe_catches_denied_or_forbidden_response_bytes(leak: str) -> None:
    with _fake_client(leak=leak) as client:
        with pytest.raises(RouteProbeError):
            probe_local_customer_routes(CONFIG, client=client)


def test_probe_catches_incomplete_or_malformed_sse() -> None:
    with _fake_client(bad_sse=True) as client:
        with pytest.raises(RouteProbeError, match="SSE"):
            probe_local_customer_routes(CONFIG, client=client)


def test_probe_refuses_redirect_to_external_host() -> None:
    with _fake_client(redirect=True) as client:
        with pytest.raises(RouteProbeError, match="redirected"):
            probe_local_customer_routes(CONFIG, client=client)


@pytest.mark.parametrize("url", [
    "http://example.com:9000",
    "http://169.254.169.254/latest/meta-data",
    "http://127.0.0.1.evil.invalid",
    "https://127.0.0.1:9000",
    "http://root:secret@127.0.0.1:9000",
])
def test_probe_rejects_unsafe_destinations(url: str) -> None:
    with pytest.raises(RouteProbeError):
        probe_local_customer_routes(RouteProbeConfig(**{**CONFIG.__dict__, "base_url": url}))


@pytest.mark.parametrize("path", ["//evil.invalid", "/a/../admin", "/chat?private=true", "/chat#fragment"])
def test_probe_rejects_ambiguous_routes(path: str) -> None:
    with pytest.raises(RouteProbeError):
        probe_local_customer_routes(RouteProbeConfig(**{**CONFIG.__dict__, "json_path": path}))


def test_probe_must_refuse_caller_supplied_client_with_different_remote_origin() -> None:
    # Supplying a safe config.base_url does not make the *actual* HTTP client
    # safe. A remote client could otherwise receive employee test credentials.
    remote = httpx.Client(
        base_url="https://external.example.invalid",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={
            "answer": "PUBLIC_TEST_CONTENT",
        })),
    )
    try:
        with pytest.raises(RouteProbeError, match="origin|loopback|client|isolated local HTTP"):
            probe_local_customer_routes(CONFIG, client=remote)
    finally:
        remote.close()


def test_probe_cannot_follow_redirects_even_when_caller_enables_them() -> None:
    followed = []

    def redirecting(request: httpx.Request) -> httpx.Response:
        followed.append(str(request.url))
        if request.url.path.startswith("/v1/"):
            return httpx.Response(
                302, headers={"Location": "http://127.0.0.1:45555/redirect-target"},
            )
        return httpx.Response(200, json={"answer": "PUBLIC_TEST_CONTENT"})

    with httpx.Client(
        base_url=CONFIG.base_url,
        transport=httpx.MockTransport(redirecting),
        follow_redirects=True,
    ) as client:
        with pytest.raises(RouteProbeError, match="redirect"):
            probe_local_customer_routes(CONFIG, client=client)
    assert all("/redirect-target" not in url for url in followed)


@pytest.mark.parametrize("channel", ["json", "sse"])
def test_route_probe_must_decode_escaped_answer_before_claiming_no_leak(channel: str) -> None:
    # A real UI decodes JSON and SSE data. Raw UTF-8 substring scanning
    # misses escaped Unicode representations of the same protected secret.
    def responder(request: httpx.Request) -> httpx.Response:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        stream = request.url.path.endswith("/stream")
        if token == "invalid-token":
            return httpx.Response(401, json={"detail": "Unauthorized"})
        if token == "auth-good":
            answer = "PUBLIC_TEST_CONTENT"
        else:
            answer = "Access denied"
            if (channel == "sse" and stream) or (channel == "json" and not stream):
                answer = "PRIVATE_TEST_SECRET"
        encoded = answer.replace("PRIVATE", r"\u0050RIVATE")
        if stream:
            payload = 'event: token\ndata: "' + encoded + '"\n\nevent: complete\ndata: {}\n\n'
            return httpx.Response(200, content=payload, headers={"content-type": "text/event-stream"})
        payload = '{"answer":"' + encoded + '"}'
        return httpx.Response(200, content=payload, headers={"content-type": "application/json"})
    with httpx.Client(base_url=CONFIG.base_url, transport=httpx.MockTransport(responder)) as client:
        with pytest.raises(RouteProbeError, match="UNAUTHORIZED_CANARY_RELEASED"):
            probe_local_customer_routes(CONFIG, client=client)

def test_invalid_identity_error_response_must_decode_hidden_canary() -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        if token == "invalid-token":
            return httpx.Response(401, content=r'{"detail":"\u0050RIVATE_TEST_SECRET"}',
                                  headers={"content-type": "application/json"})
        value = "PUBLIC_TEST_CONTENT" if token == "auth-good" else "Access denied"
        if request.url.path.endswith("/stream"):
            return httpx.Response(200, content=(
                f"event: token\ndata: {json.dumps(value)}\n\nevent: complete\ndata: {{}}\n\n"
            ), headers={"content-type": "text/event-stream"})
        return httpx.Response(200, json={"answer": value})
    with httpx.Client(base_url=CONFIG.base_url, transport=httpx.MockTransport(responder)) as client:
        with pytest.raises(RouteProbeError, match="UNAUTHORIZED_CANARY_RELEASED"):
            probe_local_customer_routes(CONFIG, client=client)
