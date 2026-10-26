"""Validate the actual customer RAG HTTP route after operator-approved cutover.

A successful Gateway-only test is NOT deployment proof. This helper only
supports the explicit reference Compose contract and a localhost-published
customer RAG /v1/chat/completions route. It never changes customer resources.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from .customer_agent import CustomerAgentError, verify_deployment_contract
from .installer import InstallationSpec


@dataclass(frozen=True)
class EmployeeRouteProbe:
    url: str
    allowed_token: str
    denied_token: str
    allowed_resources: list[dict[str, Any]]
    denied_resources: list[dict[str, Any]]
    allowed_canary: str
    forbidden_canary: str

    @classmethod
    def parse(cls, data: dict[str, Any]) -> "EmployeeRouteProbe":
        if set(data) != {
            "url", "allowed_token", "denied_token", "allowed_resources",
            "denied_resources", "allowed_canary", "forbidden_canary",
        }:
            raise CustomerAgentError("Invalid employee-facing probe configuration")
        try:
            result = cls(**data)
        except TypeError as exc:
            raise CustomerAgentError("Incomplete customer RAG probe") from exc
        if (not all(isinstance(v, str) and 0 < len(v) <= 16_384
                    for v in (result.allowed_token, result.denied_token))
                or result.allowed_token == result.denied_token
                or not isinstance(result.allowed_resources, list) or not result.allowed_resources
                or not isinstance(result.denied_resources, list) or not result.denied_resources
                or any(not isinstance(resource, dict) for resource in [
                    *result.allowed_resources, *result.denied_resources
                ])
                or not isinstance(result.allowed_canary, str) or len(result.allowed_canary) < 12
                or not isinstance(result.forbidden_canary, str) or len(result.forbidden_canary) < 12
                or result.allowed_canary == result.forbidden_canary):
            raise CustomerAgentError("Reference employee-route test inputs are invalid")
        return result


def _parsed_reference_route(raw: str) -> tuple[str, int]:
    if not isinstance(raw, str):
        raise CustomerAgentError("Employee RAG route must be an explicit loopback HTTP URL")
    parsed = urlsplit(raw)
    if (parsed.scheme != "http" or parsed.path != "/v1/chat/completions"
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or not parsed.port):
        raise CustomerAgentError("Employee route must be a published local reference-chat endpoint")
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as exc:
        raise CustomerAgentError("Employee route must be an IP loopback address") from exc
    if address != ipaddress.IPv4Address("127.0.0.1"):
        raise CustomerAgentError("Employee route must use the authorized 127.0.0.1 binding")
    return str(address), parsed.port


def verify_published_customer_route(
    *, resolved_compose: dict[str, Any], rag_service: str, url: str,
    gateway_port: int,
) -> None:
    """Confirm a RAG service, not the Gateway, owns the loopback port."""
    _, port = _parsed_reference_route(url)
    if port == gateway_port:
        raise CustomerAgentError("Gateway-only tests do not certify employee RAG cutover")
    services = resolved_compose.get("services")
    rag = services.get(rag_service) if isinstance(services, dict) else None
    if not isinstance(rag, dict):
        raise CustomerAgentError("Customer RAG service is absent")
    exposed = False
    for item in rag.get("ports") or []:
        if isinstance(item, dict):
            published = item.get("published")
            host_ip = item.get("host_ip")
            protocol = item.get("protocol", "tcp")
            exposed |= (str(published) == str(port) and host_ip == "127.0.0.1"
                        and protocol == "tcp")
        elif isinstance(item, str):
            exposed |= item in {
                f"127.0.0.1:{port}:8000", f"127.0.0.1:{port}:8090",
            }
    if not exposed:
        raise CustomerAgentError("Employee route is not a loopback-published customer RAG port")


def _body_json_bytes(
    client: httpx.Client, *,
    url: str, token: str, application_id: str,
    request_id: str, resources: list[dict[str, Any]],
    max_bytes: int = 1_000_000,
) -> tuple[int, bytes, dict[str, Any]]:
    with client.stream("POST", url, follow_redirects=False,
                       headers={"Authorization": f"Bearer {token}"},
                       json={"application_id": application_id,
                             "request_id": request_id,
                             "employee_question": "Approved synthetic employee route verification.",
                             "retrieved_resources": resources}) as response:
        chunks: list[bytes] = []
        size = 0
        for part in response.iter_bytes():
            size += len(part)
            if size > max_bytes:
                raise CustomerAgentError("Customer RAG response exceeded the reference output gate")
            chunks.append(part)
        raw = b"".join(chunks)
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise CustomerAgentError("Customer RAG returned an invalid JSON response") from exc
        if not isinstance(payload, dict):
            raise CustomerAgentError("Customer RAG output must be a JSON object")
        return response.status_code, raw, payload


def probe_customer_employee_route(
    *, installation: dict[str, Any], spec: InstallationSpec,
    resolved_compose: dict[str, Any], nonce: str,
    probe: EmployeeRouteProbe, client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Produce limited evidence from real employee-facing allow+deny calls."""
    verify_deployment_contract(
        installation=installation, spec=spec, resolved_compose=resolved_compose,
    )
    verify_published_customer_route(
        resolved_compose=resolved_compose, rag_service=spec.rag_service,
        url=probe.url, gateway_port=spec.listen_port,
    )
    if not isinstance(nonce, str) or len(nonce) < 32:
        raise CustomerAgentError("The issued server nonce is missing")
    digest = hashlib.sha256(nonce.encode()).hexdigest()[:24]
    request_id = "ap-cutover-" + digest
    own = client is None
    http = client or httpx.Client(timeout=15, follow_redirects=False, trust_env=False)
    try:
        success, success_raw, success_data = _body_json_bytes(
            http, url=probe.url, token=probe.allowed_token,
            application_id=spec.application_id, request_id=request_id,
            resources=probe.allowed_resources,
        )
        if success != 200:
            raise CustomerAgentError("Customer RAG allowed positive control did not succeed")
        metadata = success_data.get("accessproof")
        decision_id = metadata.get("decision_id") if isinstance(metadata, dict) else None
        if (not isinstance(metadata, dict) or metadata.get("decision") != "allow"
                or not isinstance(decision_id, str) or not decision_id
                or probe.allowed_canary not in json.dumps(success_data, ensure_ascii=False)
                or probe.forbidden_canary in json.dumps(success_data, ensure_ascii=False)):
            raise CustomerAgentError("Employee RAG did not return a verified allowed result")
        denial_status, denial_raw, denial_data = _body_json_bytes(
            http, url=probe.url, token=probe.denied_token,
            application_id=spec.application_id, request_id=request_id + "-deny",
            resources=probe.denied_resources,
        )
        detail = denial_data.get("detail")
        if (denial_status != 403
                or not isinstance(detail, dict)
                or detail.get("code") != "NO_AUTHORIZED_RESOURCES"
                or probe.forbidden_canary in json.dumps(denial_data, ensure_ascii=False)
                or probe.allowed_canary in json.dumps(denial_data, ensure_ascii=False)):
            raise CustomerAgentError("Customer RAG did not deny the unauthorized employee")
        # This third employee-facing request deliberately modifies signed
        # resource CONTENT while retaining the provider's attestation. Layer 1
        # must still authorize the document but the signed-content boundary
        # must reject the tampered bytes before model generation.
        signed = next((item for item in probe.allowed_resources
                       if isinstance(item.get("content"), str)
                       and isinstance(item.get("content_attestation"), str)
                       and item["content_attestation"]), None)
        if signed is None:
            raise CustomerAgentError("Tamper certification requires signed allowed source chunks")
        forged = dict(signed)
        forged["content"] += "\nACCESSPROOF_FORGED_SOURCE_SENTINEL\n"
        forged_status, forged_raw, forged_data = _body_json_bytes(
            http, url=probe.url, token=probe.allowed_token,
            application_id=spec.application_id,
            request_id=request_id + "-tamper", resources=[forged],
        )
        forged_detail = forged_data.get("detail")
        if (forged_status != 503
                or not isinstance(forged_detail, dict)
                or forged_detail.get("code") != "SOURCE_CONTENT_ATTESTATION_FAILED"
                or probe.forbidden_canary in json.dumps(forged_data, ensure_ascii=False)
                or probe.allowed_canary in json.dumps(forged_data, ensure_ascii=False)):
            raise CustomerAgentError("Forged source was not blocked by the actual RAG protection route")
        return {
            "tamper_request_id": request_id + "-tamper",
            "tamper_http_status": forged_status,
            "tamper_response_sha256": hashlib.sha256(forged_raw).hexdigest(),
            "tamper_reason_code": "SOURCE_CONTENT_ATTESTATION_FAILED",
            "application_request_id": request_id,
            "application_http_status": success,
            "application_response_sha256": hashlib.sha256(success_raw).hexdigest(),
            "decision_id": decision_id,
            "forbidden_canary_observed": False,
            "gateway_route_enforced": True,
            "negative_request_id": request_id + "-deny",
            "negative_http_status": denial_status,
            "negative_response_sha256": hashlib.sha256(denial_raw).hexdigest(),
            "negative_reason_code": "NO_AUTHORIZED_RESOURCES",
            "negative_forbidden_canary_observed": False,
        }
    finally:
        if own:
            http.close()
