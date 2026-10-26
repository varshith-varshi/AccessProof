from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from apps.gateway.accessproof_gateway.challenge_agent import GatewayRouteChallenge
from apps.gateway.accessproof_gateway.customer_agent import (
    CustomerAgentError, submit_customer_reference_probe, verify_deployment_contract,
)
from apps.gateway.accessproof_gateway.installer import InstallationSpec
from apps.gateway.accessproof_gateway.network_boundary import NetworkBoundaryError


def _scenario(tmp_path: Path):
    original = tmp_path / "customer.yml"
    original.write_text("services: customer-rag\n", encoding="utf-8")
    override = tmp_path / "override.json"
    override.write_text('{"approved":"customer-rag"}', encoding="utf-8")
    key = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    spec = InstallationSpec.parse({
        "tenant_id": "tenant-synthetic", "application_id": "app-synthetic",
        "rag_service": "customer-rag", "guard_url": "http://guard:8080",
        "model_url": "http://model:8000/v1/chat/completions", "listen_port": 18108,
        "trusted_public_keys": {"key": base64.urlsafe_b64encode(key).decode().rstrip("=")},
    })
    gateway_url = "http://127.0.0.1:18108/v1/chat/completions"
    install = {
        "customer_compose": str(original), "override": str(override),
        "tenant_id": spec.tenant_id, "application_id": spec.application_id,
        "reference_contract": "accessproof.gateway/v1",
        "deployment_sha256": hashlib.sha256(
            b"accessproof.gateway.compose/v1\0" + original.read_bytes()
            + b"\0" + override.read_bytes()
        ).hexdigest(),
        "route_sha256": hashlib.sha256(gateway_url.encode()).hexdigest(),
    }
    compose = {
        "networks": {"rag-iso": {"internal": True}, "model-private": {"internal": True},
                     "guard-private": {"internal": True},
                     "accessproof-gateway-host": {"internal": False}},
        "services": {
            "customer-rag": {
                "labels": {
                    "com.accessproof.gateway.contract": "accessproof.gateway/v1",
                    "com.accessproof.gateway.enforces": "attested-retrieval-and-buffered-output",
                    "com.accessproof.gateway.route_env": "ACCESSPROOF_CHAT_URL",
                },
                "environment": {"ACCESSPROOF_CHAT_URL": "http://accessproof-gateway:8090/v1/chat/completions"},
                "networks": ["rag-iso"],
            },
            "accessproof-gateway": {
                "read_only": True, "cap_drop": ["ALL"],
                "networks": ["rag-iso", "model-private", "guard-private", "accessproof-gateway-host"],
            },
            "model": {"networks": ["model-private"]},
            "guard": {"networks": ["guard-private"]},
        },
    }
    challenge = {
        "url": gateway_url, "application_id": spec.application_id,
        "challenge_id": "123e4567-e89b-12d3-a456-426614174000",
        "challenge_nonce": "x" * 40,
        "forbidden_canary": "UNAUTHORIZED_CANARY",
        "allowed_canary": "PUBLIC_TEST_ANSWER",
        "probes": [
            {"name": name, "employee_token": "synthetic-" + name,
             "retrieved_resources": [{"source_id": "test", "resource_id": "doc"}],
             "expect_status": {"allow": [200], "deny": [403],
                               "tamper": [503], "layer2_revoke": [403]}[name]}
            for name in ("allow", "deny", "tamper", "layer2_revoke")
        ],
    }
    machine = {"guard_id": "guard-synthetic", "credential": "machine-test-credential",
               "control_plane_url": "http://127.0.0.1:8000"}
    return spec, install, compose, challenge, machine


def test_installer_change_invalidates_machine_reference_certification(tmp_path):
    spec, install, compose, _, _ = _scenario(tmp_path)
    assert verify_deployment_contract(
        installation=install, spec=spec, resolved_compose=compose
    )["static_egress_isolated"]
    Path(install["customer_compose"]).write_text("modified=1")
    with pytest.raises(CustomerAgentError, match="changed"):
        verify_deployment_contract(installation=install, spec=spec,
                                   resolved_compose=compose)


def test_machine_rejects_direct_model_network_bypass(tmp_path):
    spec, install, compose, _, _ = _scenario(tmp_path)
    compose["services"]["customer-rag"]["networks"].append("model-private")
    with pytest.raises(NetworkBoundaryError):
        verify_deployment_contract(installation=install, spec=spec,
                                   resolved_compose=compose)


def test_machine_submits_only_local_synthetic_observations(monkeypatch, tmp_path):
    spec, install, compose, challenge, machine = _scenario(tmp_path)
    seen = []

    def local_run(self):
        seen.append(self.application_id)
        return {"status": "PASS_LOCAL_REFERENCE_ONLY", "probes": [
            {"name": item["name"]} for item in challenge["probes"]
        ]}

    monkeypatch.setattr(GatewayRouteChallenge, "run", local_run)

    def server(req: httpx.Request) -> httpx.Response:
        assert req.headers["Authorization"] == "Bearer machine-test-credential"
        received = json.loads(req.content)
        assert received["customer_route_verified"] is True
        assert received["deployment_sha256"] == install["deployment_sha256"]
        assert "synthetic-allow" not in req.content.decode()
        return httpx.Response(202, json={"state": "tested_awaiting_customer_cutover"})

    with httpx.Client(base_url="http://127.0.0.1:8000",
                      transport=httpx.MockTransport(server)) as client:
        result = submit_customer_reference_probe(
            installation=install, challenge_config=challenge,
            machine_credentials=machine, spec=spec,
            resolved_compose=compose, client=client,
        )
    assert seen == [spec.application_id]
    assert result["production_certification"] is False



def test_machine_retries_only_genuine_delayed_guard_audit_upload(monkeypatch, tmp_path):
    spec, install, compose, challenge, machine = _scenario(tmp_path)
    monkeypatch.setattr(GatewayRouteChallenge, "run", lambda self: {
        "status": "PASS_LOCAL_REFERENCE_ONLY",
        "probes": [{"name": item["name"]} for item in challenge["probes"]],
    })
    attempts = []
    def server(req):
        attempts.append(req)
        if len(attempts) == 1:
            return httpx.Response(409, json={"detail": {"code": "GUARD_AUDIT_EVIDENCE_MISSING"}})
        return httpx.Response(202, json={"state": "tested_awaiting_customer_cutover"})
    with httpx.Client(base_url="http://127.0.0.1:8000",
                      transport=httpx.MockTransport(server)) as client:
        result = submit_customer_reference_probe(
            installation=install, challenge_config=challenge,
            machine_credentials=machine, spec=spec,
            resolved_compose=compose, client=client,
            audit_wait_attempts=2, audit_wait_interval_seconds=0,
        )
    assert len(attempts) == 2
    assert result["production_certification"] is False
