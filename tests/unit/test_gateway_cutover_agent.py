"""Reference employee-RAG cutover must observe both real HTTP authorization outcomes."""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from apps.gateway.accessproof_gateway.cutover_agent import (
    EmployeeRouteProbe, probe_customer_employee_route, verify_published_customer_route,
)
from apps.gateway.accessproof_gateway.customer_agent import CustomerAgentError, verify_deployment_contract
from apps.gateway.accessproof_gateway.network_boundary import NetworkBoundaryError
from tests.unit.test_gateway_customer_agent import _scenario


def _probe():
    return EmployeeRouteProbe.parse({
        "url": "http://127.0.0.1:18108/v1/chat/completions",
        "allowed_token": "verified-synthetic-allow",
        "denied_token": "verified-synthetic-deny",
        "allowed_resources": [{"resource_id": "allowed", "content": "AUTHORIZED_PUBLIC_REFERENCE",
                                "content_attestation": "synthetic-signed-content-fixture"}],
        "denied_resources": [{"resource_id": "secret", "content": "UNAUTHORIZED_PRIVATE_CANARY"}],
        "allowed_canary": "AUTHORIZED_PUBLIC_REFERENCE",
        "forbidden_canary": "UNAUTHORIZED_PRIVATE_CANARY",
    })


def _prepared(tmp_path: Path):
    spec, installation, compose, _, _ = _scenario(tmp_path)
    compose["services"]["accessproof-gateway"]["ports"] = [
        {"published": "18108", "target": 8090, "host_ip": "127.0.0.1", "protocol": "tcp"}
    ]
    return spec, installation, compose


def _mock_prechecked_topology_for_http_unit(monkeypatch):
    # Route response/body tests below exercise the HTTP three-control logic in
    # isolation. A published RAG port is *never* allowed in real certification:
    # verify_deployment_contract rejects it as an unprotected bypass route.
    monkeypatch.setattr(
        "apps.gateway.accessproof_gateway.cutover_agent.verify_deployment_contract",
        lambda **kwargs: {"static_egress_isolated": True},
    )
    monkeypatch.setattr(
        "apps.gateway.accessproof_gateway.cutover_agent.verify_published_customer_route",
        lambda **kwargs: None,
    )


def test_published_rag_port_is_rejected_before_http_probes(tmp_path):
    spec, installation, compose = _prepared(tmp_path)
    compose["services"]["customer-rag"]["ports"] = [
        {"published": "18081", "target": 8000, "host_ip": "127.0.0.1", "protocol": "tcp"}
    ]
    with pytest.raises(NetworkBoundaryError, match="RAG published ports can bypass"):
        verify_deployment_contract(
            installation=installation, spec=spec, resolved_compose=compose,
        )


def test_employee_cutover_probes_authentic_rag_endpoint_and_computes_real_http_hashes(tmp_path, monkeypatch):
    _mock_prechecked_topology_for_http_unit(monkeypatch)
    spec, installation, compose = _prepared(tmp_path)
    seen = []
    def serve(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        seen.append((req.url.path, body["request_id"]))
        if body["request_id"].endswith("-tamper"):
            assert body["retrieved_resources"][0]["content"].endswith("ACCESSPROOF_FORGED_SOURCE_SENTINEL\n")
            return httpx.Response(503, json={
                "detail": {"code": "SOURCE_CONTENT_ATTESTATION_FAILED"},
            })
        if req.headers["Authorization"] == "Bearer verified-synthetic-allow":
            return httpx.Response(200, json={
                "choices": [{"message": {"content": "AUTHORIZED_PUBLIC_REFERENCE"}}],
                "accessproof": {"decision": "allow", "decision_id": "guard-allowed"},
            })
        return httpx.Response(403, json={"detail": {"code": "NO_AUTHORIZED_RESOURCES"}})

    with httpx.Client(base_url="http://127.0.0.1:18108",
                      transport=httpx.MockTransport(serve)) as client:
        receipt = probe_customer_employee_route(
            installation=installation, spec=spec, resolved_compose=compose,
            nonce="nonce-" + "a" * 40, probe=_probe(), client=client,
        )
    assert len(seen) == 3
    assert all(path == "/v1/chat/completions" for path, _ in seen)
    assert seen[1][1] == seen[0][1] + "-deny"
    assert seen[2][1] == seen[0][1] + "-tamper"
    assert receipt["application_http_status"] == 200
    assert receipt["negative_http_status"] == 403
    assert receipt["tamper_http_status"] == 503
    assert receipt["decision_id"] == "guard-allowed"
    assert len(receipt["application_response_sha256"]) == 64
    assert "verified-synthetic-allow" not in json.dumps(receipt)


def test_employee_route_rejects_unpublished_or_non_gateway_endpoint(tmp_path):
    spec, _, compose = _prepared(tmp_path)
    for candidate in [
        "http://127.0.0.1:18081/v1/chat/completions",
        "http://169.254.169.254:18081/v1/chat/completions",
        "https://127.0.0.1:18081/v1/chat/completions",
        "http://127.0.0.1:18082/v1/chat/completions",
        "http://127.0.0.1:18081/v1/chat/completions?bypass=1",
    ]:
        with pytest.raises(CustomerAgentError):
            verify_published_customer_route(
                resolved_compose=compose, rag_service=spec.rag_service,
                url=candidate, gateway_port=spec.listen_port,
            )


@pytest.mark.parametrize("case", [
    "all_200", "wrong_decision", "missing_positive_canary", "private_leak",
    "wrong_denial_code", "denied_canary_leak", "wrong_positive_path",
    "tamper_failed_open", "tamper_wrong_reason", "tamper_leaks_content",
])
def test_customer_route_protection_fails_closed_for_bypass_scenarios(tmp_path, case, monkeypatch):
    _mock_prechecked_topology_for_http_unit(monkeypatch)
    spec, installation, compose = _prepared(tmp_path)
    def reply(req: httpx.Request) -> httpx.Response:
        is_allow = req.headers["Authorization"].endswith("verified-synthetic-allow")
        if case == "wrong_positive_path":
            return httpx.Response(404, json={"detail": {"code": "NOT_FOUND"}})
        if json.loads(req.content)["request_id"].endswith("-tamper"):
            reason = "LAYER2_ACCESS_REVOKED" if case == "tamper_wrong_reason" else "SOURCE_CONTENT_ATTESTATION_FAILED"
            text = "UNAUTHORIZED_PRIVATE_CANARY" if case == "tamper_leaks_content" else "blocked"
            return httpx.Response(200 if case == "tamper_failed_open" else 503,
                                  json={"detail": {"code": reason, "message": text}})
        if is_allow:
            decision = "would_allow" if case == "wrong_decision" else "allow"
            content = (
                "UNAUTHORIZED_PRIVATE_CANARY" if case == "private_leak"
                else "NO_CANARY" if case == "missing_positive_canary"
                else "AUTHORIZED_PUBLIC_REFERENCE"
            )
            return httpx.Response(200, json={
                "choices": [{"message": {"content": content}}],
                "accessproof": {"decision": decision, "decision_id": "guard-allow"},
            })
        reason = "LAYER2_ACCESS_REVOKED" if case == "wrong_denial_code" else "NO_AUTHORIZED_RESOURCES"
        message = "UNAUTHORIZED_PRIVATE_CANARY" if case == "denied_canary_leak" else "blocked"
        return httpx.Response(200 if case == "all_200" else 403, json={
            "detail": {"code": reason, "message": message},
        })

    with httpx.Client(base_url="http://127.0.0.1:18081",
                      transport=httpx.MockTransport(reply)) as client:
        with pytest.raises(CustomerAgentError):
            probe_customer_employee_route(
                installation=installation, spec=spec, resolved_compose=compose,
                nonce="nonce-" + "a" * 40, probe=_probe(), client=client,
            )


def test_employee_probe_never_accepts_missing_identity_or_unverified_origin():
    data = {
        "url": "http://127.0.0.1:18081/v1/chat/completions",
        "allowed_token": "same", "denied_token": "same",
        "allowed_resources": [{"source_id": "drive"}],
        "denied_resources": [{"source_id": "drive"}],
        "allowed_canary": "AUTHORIZED_PUBLIC_REFERENCE",
        "forbidden_canary": "UNAUTHORIZED_PRIVATE_CANARY",
    }
    with pytest.raises(CustomerAgentError):
        EmployeeRouteProbe.parse(data)
