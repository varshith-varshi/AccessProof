from __future__ import annotations

import base64
import ipaddress
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, cast
from urllib.parse import urlparse, urlunparse

import httpx

from packages.connector_sdk.target import AITargetAdapter, TargetObservation
from packages.domain.models import Principal

_TOKEN = re.compile(r"{{\s*(probe|principal\.external_id|principal\.email|principal\.access_token|session\.id)\s*}}")


def render_template(value: Any, *, prompt: str, principal: Principal) -> Any:
    if isinstance(value, str):

        def repl(match: re.Match[str]) -> str:
            key = match.group(1)
            if key == "probe":
                return prompt
            if key == "principal.external_id":
                return principal.external_id
            if key == "principal.email":
                return principal.email or ""
            if key == "principal.access_token":
                return principal.access_token or ""
            if key == "session.id":
                return principal.session_id or ""
            raise ValueError("unsupported template variable")

        rendered = _TOKEN.sub(repl, value)
        if "{{" in rendered or "}}" in rendered:
            raise ValueError("unsupported template expression")
        return rendered
    if isinstance(value, list):
        return [render_template(v, prompt=prompt, principal=principal) for v in value]
    if isinstance(value, dict):
        return {k: render_template(v, prompt=prompt, principal=principal) for k, v in value.items()}
    return value


def _extract(data: Any, path: str | None, default: Any) -> Any:
    if not path:
        return default
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def _extract_evidence(data: Any, path: str | None) -> list[str] | None:
    """Extract string or object evidence, including paths such as chunks[].content."""
    value = _extract(data, path, None)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    if value is None and path and "[]" not in path:
        return []
    if not path or "[]" not in path:
        return None
    values: list[Any] = [data]
    for part in path.split("."):
        expanded: list[Any] = []
        is_array = part.endswith("[]")
        key = part[:-2] if is_array else part
        for current in values:
            if not isinstance(current, dict) or key not in current:
                continue
            child = current[key]
            if is_array:
                if isinstance(child, list):
                    expanded.extend(child)
            else:
                expanded.append(child)
        values = expanded
    if not values:
        return []
    return [item if isinstance(item, str) else json.dumps(item, sort_keys=True) for item in values]


def _resolve_public_addresses(url: str) -> tuple[str, ...]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Cloud AI targets must use HTTPS with a hostname")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost") or hostname.endswith(".internal"):
        raise ValueError("Blocked target hostname")
    try:
        infos = socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Target hostname could not be resolved") from exc

    addresses: set[str] = set()
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        # Cloud mode is intentionally strict: only globally routable addresses are
        # accepted. Internal, loopback, link-local, CGNAT, multicast, unspecified,
        # documentation/reserved, and private IPv4/IPv6 must use a private runner.
        if not ip.is_global:
            raise ValueError("Non-global target addresses require private runner mode")
        addresses.add(ip.compressed)
    if not addresses:
        raise ValueError("Target hostname resolved to no usable addresses")
    return tuple(sorted(addresses))


def validate_cloud_url(url: str) -> None:
    _resolve_public_addresses(url)


def _pin_https_url(url: str) -> tuple[str, str, str]:
    """Return a public-IP-pinned URL plus Host/SNI for the original hostname.

    HTTPX's documented `sni_hostname` extension preserves certificate hostname
    verification while the TCP connection targets the already-validated IP. This
    avoids a DNS-rebinding window between URL validation and connection setup.
    """
    parsed = urlparse(url)
    ip = ipaddress.ip_address(_resolve_public_addresses(url)[0])
    explicit = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    if parsed.port is not None and parsed.port != 443:
        explicit = f"{explicit}:{parsed.port}"
    pinned = urlunparse(
        (parsed.scheme, explicit, parsed.path or "/", parsed.params, parsed.query, parsed.fragment)
    )
    host_header = parsed.hostname or ""
    if parsed.port is not None and parsed.port != 443:
        host_header = f"{host_header}:{parsed.port}"
    return pinned, host_header, parsed.hostname or ""


@dataclass(slots=True)
class HttpTargetConfig:
    url: str
    method: str = "POST"
    request_body: dict[str, Any] = field(
        default_factory=lambda: {"message": "{{ probe }}", "user_id": "{{ principal.external_id }}"}
    )
    static_headers: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None
    api_key_header: str | None = None
    api_key_value: str | None = None
    basic_username: str | None = None
    basic_password: str | None = None
    oauth_token_url: str | None = None
    oauth_client_id: str | None = None
    oauth_client_secret: str | None = None
    oauth_scope: str | None = None
    mtls_cert_file: str | None = None
    mtls_key_file: str | None = None
    mtls_ca_file: str | None = None
    answer_path: str | None = "answer"
    citations_path: str | None = "citations"
    retrieved_documents_path: str | None = "retrieved_documents"
    tool_outputs_path: str | None = "tool_outputs"
    runner_mode: bool = False
    timeout_seconds: float = 30.0
    session_strategy: str = "STATELESS"
    session_create_url: str | None = None
    session_create_body: dict[str, Any] = field(default_factory=dict)
    session_id_path: str | None = None


class GenericHttpTarget(AITargetAdapter):
    def __init__(self, config: HttpTargetConfig):
        self.config = config
        parsed = urlparse(config.url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError("AI target must use HTTP(S) without URL credentials")
        if config.method.upper() not in {"GET", "POST"}:
            raise ValueError("AI target method must be GET or POST")
        if config.session_strategy not in {"STATELESS", "NEW_SESSION_PER_PROBE", "ONE_SESSION_PER_RUN", "CUSTOM_SESSION"}:
            raise ValueError("Unsupported session strategy")
        if not config.runner_mode:
            validate_cloud_url(config.url)
            if config.oauth_token_url:
                validate_cloud_url(config.oauth_token_url)
            if config.session_create_url:
                validate_cloud_url(config.session_create_url)
            if config.mtls_cert_file or config.mtls_key_file or config.mtls_ca_file:
                raise ValueError("mTLS file configuration is permitted only in private runner mode")

        ssl_context = (
            ssl.create_default_context(cafile=config.mtls_ca_file)
            if config.mtls_ca_file
            else ssl.create_default_context()
        )
        if config.mtls_cert_file:
            ssl_context.load_cert_chain(config.mtls_cert_file, keyfile=config.mtls_key_file)
        elif config.mtls_key_file:
            raise ValueError("mtls_key_file requires mtls_cert_file")

        self._client = httpx.AsyncClient(
            timeout=config.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            verify=ssl_context,
        )
        self._oauth_token: str | None = None
        self._oauth_expires_at = 0.0
        self._run_session_id: str | None = None

    async def _create_session(self, principal: Principal) -> str | None:
        if not self.config.session_create_url:
            return None
        body = render_template(self.config.session_create_body, prompt="", principal=principal)
        try:
            response = await self._client.post(self.config.session_create_url, json=body, headers=await self._headers(principal=principal))
            response.raise_for_status()
            value = _extract(response.json(), self.config.session_id_path, None)
        except (httpx.HTTPError, ValueError, OSError):
            return None
        return value if isinstance(value, str) and value else None

    async def _apply_session_strategy(self, principal: Principal) -> bool:
        strategy = self.config.session_strategy
        if strategy == "STATELESS":
            principal.session_id = None
            return True
        if strategy == "CUSTOM_SESSION":
            return bool(principal.session_id)
        if strategy == "ONE_SESSION_PER_RUN" and self._run_session_id:
            principal.session_id = self._run_session_id
            return True
        session_id = await self._create_session(principal)
        if not session_id:
            return False
        principal.session_id = session_id
        if strategy == "ONE_SESSION_PER_RUN":
            self._run_session_id = session_id
        return True

    async def _oauth_bearer(self) -> str | None:
        if not self.config.oauth_token_url:
            return None
        if not self.config.oauth_client_id or not self.config.oauth_client_secret:
            raise ValueError("OAuth client credentials require client_id and client_secret")
        if self._oauth_token and time.monotonic() < self._oauth_expires_at:
            return self._oauth_token

        data = {"grant_type": "client_credentials"}
        if self.config.oauth_scope:
            data["scope"] = self.config.oauth_scope
        token_url = self.config.oauth_token_url
        headers: dict[str, str] = {"Accept": "application/json"}
        extensions = None
        if not self.config.runner_mode:
            token_url, host, sni = _pin_https_url(token_url)
            headers["Host"] = host
            extensions = {"sni_hostname": sni}

        response = await self._client.post(
            token_url,
            data=data,
            headers=headers,
            auth=httpx.BasicAuth(self.config.oauth_client_id, self.config.oauth_client_secret),
            extensions=extensions,
        )
        if not 200 <= response.status_code < 300:
            raise httpx.HTTPStatusError(
                "OAuth token endpoint rejected client credentials",
                request=response.request,
                response=response,
            )
        payload = response.json()
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise ValueError("OAuth token response did not include access_token")
        try:
            expires_in = max(30.0, float(payload.get("expires_in", 300)))
        except (TypeError, ValueError):
            expires_in = 300.0
        self._oauth_token = token
        self._oauth_expires_at = time.monotonic() + max(1.0, expires_in - 30.0)
        return token

    async def _headers(self, *, principal: Principal) -> dict[str, str]:
        headers = cast(
            dict[str, str],
            render_template(self.config.static_headers, prompt="", principal=principal),
        )
        oauth = await self._oauth_bearer()
        bearer = oauth or self.config.bearer_token
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        elif self.config.basic_username is not None:
            raw = f"{self.config.basic_username}:{self.config.basic_password or ''}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        if self.config.api_key_header and self.config.api_key_value:
            headers[self.config.api_key_header] = self.config.api_key_value
        return headers

    async def validate_connection(self) -> None:
        # Deliberately no speculative target request: validation happens on a
        # customer-supplied probe so AccessProof does not trigger side effects.
        if not self.config.runner_mode:
            validate_cloud_url(self.config.url)
            if self.config.oauth_token_url:
                validate_cloud_url(self.config.oauth_token_url)
            if self.config.session_create_url:
                validate_cloud_url(self.config.session_create_url)

    async def probe(self, *, principal: Principal, prompt: str) -> TargetObservation:
        if not await self._apply_session_strategy(principal):
            return TargetObservation(available=False, metadata={"error": "session_isolation_unavailable"})
        body = render_template(self.config.request_body, prompt=prompt, principal=principal)
        url = self.config.url
        try:
            headers = await self._headers(principal=principal)
            extensions = None
            if not self.config.runner_mode:
                url, host, sni = _pin_https_url(self.config.url)
                headers["Host"] = host
                extensions = {"sni_hostname": sni}
            response = await self._client.request(
                self.config.method,
                url,
                params=body if self.config.method.upper() == "GET" else None,
                json=body if self.config.method.upper() != "GET" else None,
                headers=headers,
                extensions=extensions,
            )
        except (httpx.HTTPError, ValueError, OSError):
            return TargetObservation(available=False)

        if not 200 <= response.status_code < 300:
            return TargetObservation(available=False, status_code=response.status_code)
        try:
            data = response.json()
        except (ValueError, UnicodeDecodeError):
            return TargetObservation(
                available=False,
                status_code=response.status_code,
                metadata={"error": "invalid_json"},
            )
        if not isinstance(data, dict):
            return TargetObservation(
                available=False,
                status_code=response.status_code,
                metadata={"error": "invalid_response_shape"},
            )
        missing = object()
        answer = _extract(data, self.config.answer_path, missing)
        # A missing answer/mapping is not proof of denial. Optional evidence
        # channels may be absent, but present values must match the contract.
        if not isinstance(answer, str):
            return TargetObservation(
                available=False,
                status_code=response.status_code,
                metadata={"error": "missing_or_invalid_answer"},
            )
        channels = []
        for path in (
            self.config.citations_path,
            self.config.retrieved_documents_path,
            self.config.tool_outputs_path,
        ):
            value = _extract_evidence(data, path)
            if value is None:
                return TargetObservation(
                    available=False,
                    status_code=response.status_code,
                    metadata={"error": "invalid_evidence_channel"},
                )
            channels.append(value)
        return TargetObservation(
            available=True,
            answer=answer,
            citations=channels[0],
            retrieved_documents=channels[1],
            tool_outputs=channels[2],
            status_code=response.status_code,
        )
