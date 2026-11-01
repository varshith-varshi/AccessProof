from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from apps.gateway.accessproof_gateway.customer_agent import CustomerAgentError
from apps.gateway.accessproof_gateway.customer_cutover import (
    approved_docker_cutover, verify_and_submit_customer_cutover,
)
from tests.unit.test_gateway_customer_agent import _scenario
from tests.unit.test_gateway_cutover_agent import _probe


def _cutover_setup(tmp_path: Path):
    spec, installation, compose, challenge, machine = _scenario(tmp_path)
    # The RAG must not publish a host port: doing so would create an
    # employee-accessible path that bypasses the Gateway.  These tests supply
    # an in-process HTTP mock explicitly. The employee route is exposed by the
    # Gateway, while the RAG stays on internal-only networks.
    compose["services"]["accessproof-gateway"]["ports"] = [{
        "published": "18108", "target": 8090, "host_ip": "127.0.0.1", "protocol": "tcp",
    }]
    digest = hashlib.sha256(challenge["challenge_nonce"].encode()).hexdigest()[:24]
    challenge["challenge_id"] = "123e4567-e89b-12d3-a456-426614174000"
    return spec, installation, compose, challenge, machine, digest


def test_cutover_requires_approval_before_any_docker_access(tmp_path):
    spec, installation, _, challenge, machine, _ = _cutover_setup(tmp_path)
    with patch("apps.gateway.accessproof_gateway.customer_cutover._docker") as docker:
        with pytest.raises(CustomerAgentError, match="approve"):
            approved_docker_cutover(
                installation=installation, spec=spec,
                challenge=challenge, machine=machine,
                probe=_probe(), approve=False,
            )
        docker.assert_not_called()


def test_cutover_sends_real_allow_and_deny_hashes_and_machines_cannot_skip_status(tmp_path):
    spec, installation, compose, challenge, machine, digest = _cutover_setup(tmp_path)
    seen = []
    def control_server(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if req.method == "GET":
            return httpx.Response(200, json={
                "state": "tested", "guard_id": machine["guard_id"],
                "application_id": spec.application_id,
                "deployment_sha256": installation["deployment_sha256"],
                "route_sha256": installation["route_sha256"],
            })
        payload = json.loads(req.content)
        assert payload["application_request_id"] == "ap-cutover-" + digest
        assert payload["negative_request_id"] == "ap-cutover-" + digest + "-deny"
        assert payload["tamper_request_id"] == "ap-cutover-" + digest + "-tamper"
        assert payload["tamper_http_status"] == 503
        assert payload["application_response_sha256"] != payload["negative_response_sha256"]
        assert "verified-synthetic-allow" not in req.content.decode()
        return httpx.Response(202, json={
            "state": "customer_cutover_verified", "guard_audits_matched": 3,
        })
    def rag_server(req: httpx.Request) -> httpx.Response:
        if json.loads(req.content)["request_id"].endswith("-tamper"):
            return httpx.Response(503, json={
                "detail": {"code": "SOURCE_CONTENT_ATTESTATION_FAILED"},
            })
        if req.headers["Authorization"].endswith("verified-synthetic-allow"):
            return httpx.Response(200, json={
                "choices": [{"message": {"content": "AUTHORIZED_PUBLIC_REFERENCE"}}],
                "accessproof": {"decision": "allow", "decision_id": "valid-decision"},
            })
        return httpx.Response(403, json={
            "detail": {"code": "NO_AUTHORIZED_RESOURCES"},
        })
    with httpx.Client(base_url="http://127.0.0.1:8000",
                      transport=httpx.MockTransport(control_server)) as control, httpx.Client(
                          base_url="http://127.0.0.1:18081",
                          transport=httpx.MockTransport(rag_server)) as rag:
        result = verify_and_submit_customer_cutover(
            installation=installation, spec=spec,
            challenge=challenge, machine=machine, probe=_probe(),
            resolved_compose=compose, control_client=control, rag_client=rag,
        )
    assert result["state"] == "CUSTOMER_CUTOVER_VERIFIED"
    assert result["production_certification"] is False
    assert len(seen) == 2
    assert seen[-1].headers["Authorization"] == "Bearer machine-test-credential"


def test_control_plane_missing_reference_tests_prevents_employee_route_probe(tmp_path):
    spec, installation, compose, challenge, machine, _ = _cutover_setup(tmp_path)
    with httpx.Client(base_url="http://127.0.0.1:8000", transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"state": "issued"})
    )) as control:
        with pytest.raises(CustomerAgentError):
            verify_and_submit_customer_cutover(
                installation=installation, spec=spec, challenge=challenge,
                machine=machine, probe=_probe(), resolved_compose=compose,
                control_client=control,
            )


def test_cutover_failure_after_restart_stops_only_customer_rag(tmp_path, monkeypatch):
    spec, installation, compose, challenge, machine, _ = _cutover_setup(tmp_path)
    calls = []
    monkeypatch.setattr(
        "apps.gateway.accessproof_gateway.customer_cutover._docker_compose_json",
        lambda *_: compose,
    )
    monkeypatch.setattr(
        "apps.gateway.accessproof_gateway.customer_cutover._local_gateway_ready",
        lambda *_: True,
    )
    monkeypatch.setattr(
        "apps.gateway.accessproof_gateway.customer_cutover._previous_reference_test",
        lambda **_: None,
    )
    monkeypatch.setattr(
        "apps.gateway.accessproof_gateway.customer_cutover.verify_and_submit_customer_cutover",
        lambda **_: (_ for _ in ()).throw(CustomerAgentError("denied leak")),
    )
    def fake_docker(args, *, timeout=120):
        calls.append(args)
        return None
    monkeypatch.setattr(
        "apps.gateway.accessproof_gateway.customer_cutover._docker", fake_docker,
    )
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    monkeypatch.setattr(
        "apps.gateway.accessproof_gateway.customer_cutover.httpx.Client",
        lambda **_: client,
    )
    with pytest.raises(CustomerAgentError, match="RAG_STOPPED_FAIL_CLOSED"):
        approved_docker_cutover(
            installation=installation, spec=spec, challenge=challenge,
            machine=machine, probe=_probe(), approve=True,
        )
    assert len(calls) == 2
    assert calls[0][-4:] == ["-d", "--no-deps", "--no-build", "customer-rag"]
    assert calls[1][-4:] == ["stop", "-t", "10", "customer-rag"]
    assert all("customer-rag" == command[-1] for command in calls)


def test_guard_unready_does_not_change_customer_rag(tmp_path, monkeypatch):
    spec, installation, compose, challenge, machine, _ = _cutover_setup(tmp_path)
    monkeypatch.setattr(
        "apps.gateway.accessproof_gateway.customer_cutover._docker_compose_json",
        lambda *_: compose,
    )
    monkeypatch.setattr(
        "apps.gateway.accessproof_gateway.customer_cutover._local_gateway_ready",
        lambda *_: False,
    )
    with patch("apps.gateway.accessproof_gateway.customer_cutover._docker") as docker:
        with pytest.raises(CustomerAgentError, match="not ready"):
            approved_docker_cutover(
                installation=installation, spec=spec, challenge=challenge,
                machine=machine, probe=_probe(), approve=True,
            )
        docker.assert_not_called()
