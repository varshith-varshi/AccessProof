"""Safe, independent HTTP byte observer for a local customer RAG route.

This is a *diagnostic* probe, NOT a production activation certificate.
It never grants protection, signs certification or contacts non-loopback hosts.
A Guard decision alone is never accepted as evidence of response safety.
"""
from __future__ import annotations

import ipaddress
import json
import secrets
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx


class RouteProbeError(ValueError):
    """The real customer HTTP route did not satisfy the checked boundary."""


@dataclass(frozen=True)
class RouteProbeConfig:
    base_url: str
    authorized_token: str
    denied_token: str
    allowed_canary: str
    forbidden_canary: str
    json_path: str = "/v1/protected-chat"
    sse_path: str = "/v1/protected-chat/stream"
    invalid_token: str = "synthetic-invalid-identity"


def _safe_route(path: str) -> None:
    parsed = urlsplit(path)
    if (
        not path.startswith("/") or path.startswith("//")
        or parsed.scheme or parsed.netloc or parsed.query or parsed.fragment
        or ".." in parsed.path.split("/")
        or any(ord(char) < 32 for char in path)
    ):
        raise RouteProbeError("Only relative, unambiguous local paths may be probed")


def _safe_origin(origin: str) -> None:
    parsed = urlsplit(origin)
    host = parsed.hostname
    if (
        parsed.scheme != "http" or host is None or parsed.username is not None
        or parsed.password is not None or parsed.query or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise RouteProbeError("Route probing is restricted to isolated local HTTP")
    if host == "localhost":
        return
    try:
        if not ipaddress.ip_address(host).is_loopback:
            raise RouteProbeError("Refusing to probe a non-loopback host")
    except ValueError as exc:
        raise RouteProbeError("Refusing to probe an unrecognized hostname") from exc


def _check_safe_bytes(body: bytes, config: RouteProbeConfig, *, allow_public: bool) -> None:
    if len(body) > 1_000_000:
        raise RouteProbeError("RAG output exceeded probe size limit")
    if config.forbidden_canary.encode("utf-8") in body:
        raise RouteProbeError("UNAUTHORIZED_CANARY_RELEASED")
    if not allow_public and config.allowed_canary.encode("utf-8") in body:
        raise RouteProbeError("DENIED_IDENTITY_RECEIVED_PROTECTED_CONTENT")
    if allow_public and config.allowed_canary.encode("utf-8") not in body:
        raise RouteProbeError("POSITIVE_CONTROL_DID_NOT_RECEIVE_AUTHORIZED_CONTENT")


def _decoded_strings(value: object) -> list[str]:
    # JSON escape sequences are displayed as actual characters by the
    # customer's app. Inspect every string in the decoded response tree.
    pending: list[object] = [value]
    found: list[str] = []
    visited = 0
    while pending:
        visited += 1
        if visited > 10_000:
            raise RouteProbeError("Response payload too complex to certify")
        item = pending.pop()
        if isinstance(item, str):
            found.append(item)
        elif isinstance(item, list):
            pending.extend(reversed(item))
        elif isinstance(item, dict):
            pending.extend(reversed(list(item.values())))
            pending.extend(reversed(list(item.keys())))
    return found


def _check_encoded_payload(
    content: bytes, content_type: str, config: RouteProbeConfig, *,
    stream: bool, allow_public: bool,
) -> dict[str, object] | None:
    try:
        text = content.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise RouteProbeError("Invalid UTF-8 customer response") from exc
    if not stream:
        if not content_type.startswith("application/json"):
            raise RouteProbeError("JSON endpoint returned unexpected content type")
        try:
            payload: object = json.loads(text)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise RouteProbeError("Invalid JSON response") from exc
        if not isinstance(payload, dict) or "answer" not in payload:
            raise RouteProbeError("Malformed JSON response")
        _check_safe_bytes("".join(_decoded_strings(payload)).encode("utf-8"),
                          config, allow_public=allow_public)
        return payload

    if not content_type.startswith("text/event-stream"):
        raise RouteProbeError("SSE endpoint did not emit event-stream content")
    normalized = text.replace("\r\n", "\n")
    if "event: complete\ndata: {}\n\n" not in normalized:
        raise RouteProbeError("Malformed or unfinished SSE event stream")
    # Apply the JSON decoder to *each* SSE data payload as a browser would.
    # Checking only raw JSON/SSE bytes overlooks escaped protected material.
    decoded_events: list[str] = []
    for event in normalized.split("\n\n"):
        data = "\n".join(
            line[5:].lstrip(" ") for line in event.split("\n")
            if line.startswith("data:")
        )
        if not data:
            continue
        try:
            value = json.loads(data)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise RouteProbeError("Malformed SSE data payload") from exc
        decoded_events.extend(_decoded_strings(value))
    _check_safe_bytes("".join(decoded_events).encode("utf-8"),
                      config, allow_public=allow_public)
    return None


def _body(client: httpx.Client, path: str, token: str, nonce: str) -> tuple[int, bytes, str]:
    # Streaming iterator collects the ACTUAL HTTP body bytes (not internal SDK
    # decision fields), including any illegally released early SSE events.
    with client.stream(
        "POST", path,
        headers={"Authorization": f"Bearer {token}", "Accept": "*/*"},
        json={"message": f"accessproof-test-only challenge {nonce}"},
        follow_redirects=False,
    ) as response:
        data = bytearray()
        for fragment in response.iter_bytes():
            data.extend(fragment)
            if len(data) > 1_000_000:
                raise RouteProbeError("RAG output exceeded probe size limit")
        return response.status_code, bytes(data), response.headers.get("content-type", "")


def probe_local_customer_routes(
    config: RouteProbeConfig, *, client: httpx.Client | None = None,
) -> dict[str, object]:
    """Observe authorized/denied/invalid-identity JSON and SSE bytes.

    This confirms only the routes explicitly probed. It cannot prove that a
    customer has no alternate uninstrumented routes, validate a real IdP,
    establish trusted provider content origin or certify arbitrary tool calls.
    """
    _safe_origin(config.base_url)
    _safe_route(config.json_path)
    _safe_route(config.sse_path)
    if (
        not config.authorized_token or not config.denied_token
        or not config.allowed_canary or not config.forbidden_canary
        or config.allowed_canary == config.forbidden_canary
    ):
        raise RouteProbeError("Two identities and distinct synthetic canaries are required")
    nonce = secrets.token_hex(16)
    own_client = client is None
    if client is None:
        client = httpx.Client(
            base_url=config.base_url, timeout=5,
            follow_redirects=False, trust_env=False,
        )
    else:
        # The caller's real HTTP client decides where Bearer tokens are sent,
        # not the independently checked config string. Refuse a mismatch.
        actual = str(client.base_url).rstrip("/")
        _safe_origin(actual)
        wanted = urlsplit(config.base_url)
        observed = urlsplit(actual)
        if (wanted.scheme, wanted.hostname, wanted.port) != (
            observed.scheme, observed.hostname, observed.port,
        ):
            raise RouteProbeError("Customer route probe client origin mismatch")
    checks = []
    try:
        for path, stream in ((config.json_path, False), (config.sse_path, True)):
            for identity, token, expect_allow in (
                ("authorized", config.authorized_token, True),
                ("denied", config.denied_token, False),
                ("invalid", config.invalid_token, False),
            ):
                status, content, content_type = _body(client, path, token, nonce)
                if status in (301, 302, 303, 307, 308):
                    raise RouteProbeError("RAG route redirected; scope cannot be verified")
                if identity == "invalid":
                    if status not in (401, 403, 503):
                        raise RouteProbeError("INVALID_IDENTITY_WAS_NOT_REJECTED")
                    _check_safe_bytes(content, config, allow_public=False)
                    if content_type.startswith("application/json"):
                        try:
                            parsed_error = json.loads(content)
                        except (json.JSONDecodeError, UnicodeError) as exc:
                            raise RouteProbeError("Invalid rejected-identity JSON") from exc
                        _check_safe_bytes(
                            "".join(_decoded_strings(parsed_error)).encode("utf-8"),
                            config, allow_public=False,
                        )
                else:
                    if status != 200:
                        raise RouteProbeError(f"RAG {identity} control returned unexpected HTTP {status}")
                    _check_encoded_payload(
                        content, content_type, config,
                        stream=stream, allow_public=expect_allow,
                    )
                checks.append({"route": path, "identity": identity, "status": "PASS"})
    finally:
        if own_client:
            client.close()
    return {
        "local_only": True,
        "real_http_bytes_observed": True,
        "synthetic_only": True,
        "production_certification": False,
        "scope": [config.json_path, config.sse_path],
        "checks": checks,
    }
