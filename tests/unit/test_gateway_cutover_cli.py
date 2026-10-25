from __future__ import annotations

import hashlib
import json

import httpx
import pytest

from apps.gateway.accessproof_gateway.cutover_cli import (
    CutoverError, approved_reference_cutover, _inspect_route,
)
from test_gateway_customer_agent import _scenario


def _test_config(tmp_path):
    spec, installation, compose, challenge, machine = _scenario(tmp_path)
    return spec, installation, compose, challenge, machine


def test_cutover_refuses_direct_gateway_and_external_customer_routes():
    with pytest.raises(CutoverError):
        _inspect_route("http://127.0.0.1:18108/v1/chat/completions", gateway_port=18108)
    with pytest.raises(CutoverError):
        _inspect_route("https://customer.example.com/v1/chat/completions", gateway_port=18108)


def test_customer_cutover_uses_original_service_only_after_machine_approved_test(monkeypatch, tmp_path):
    spec, install, compose, challenge, machine = _test_config(tmp_path)
    monkeypatch.setattr(
        "apps.gateway.accessproof_gateway.cutover_cli._docker_compose_json",
        lambda *args: compose,
    )
    calls = []
    def runner(command):
        calls.append(command)
    def collect(client, url, bearer, **kwargs):
        if kwargs["allowed"]:
            return {"http_status": 200, "response_sha256": "a" * 64,
                    "decision_id": "verified-guard-decision"}
        return {
            "http_status": 403 if kwargs["request_id"].endswith("-deny") else 503,
            "response_sha256": "b" * 64,
            "reason_code": ("NO_AUTHORIZED_RESOURCES" if kwargs["request_id"].endswith("-deny")
                            else "SOURCE_CONTENT_ATTESTATION_FAILED"),
        }

    monkeypatch.setattr(
        "apps.gateway.accessproof_gateway.cutover_cli._collect_response", collect,
    )
    def control_plane(req):
        if req.method == "GET":
            return httpx.Response(200, json={
                "state": "tested", "guard_id": machine["guard_id"],
                "application_id": spec.application_id,
                "deployment_sha256": install["deployment_sha256"],
                "route_sha256": install["route_sha256"],
            })
        assert req.method == "POST"
        body = json.loads(req.content)
        assert body["application_request_id"] == (
            "ap-cutover-" + hashlib.sha256(challenge["challenge_nonce"].encode()).hexdigest()[:24]
        )
        assert body["decision_id"] == "verified-guard-decision"
        assert body["tamper_reason_code"] == "SOURCE_CONTENT_ATTESTATION_FAILED"
        assert body["negative_reason_code"] == "NO_AUTHORIZED_RESOURCES"
        assert req.headers["Authorization"] == "Bearer machine-test-credential"
        return httpx.Response(202, json={"state": "customer_cutover_verified"})
    with httpx.Client(base_url="http://127.0.0.1:8000",
                      transport=httpx.MockTransport(control_plane)) as client:
        outcome = approved_reference_cutover(
            install=install, spec=spec, machine=machine,
            challenge_file=challenge,
            application_url="http://127.0.0.1:18155/v1/chat/completions",
            client=client, runner=runner,
        )
    assert outcome["state"] == "CUTOVER_VERIFIED_AWAITING_GUARD_HEARTBEAT"
    assert outcome["production_certification"] is False
    assert len(calls) == 1
    assert calls[0][-2:] == ["--force-recreate", "customer-rag"]


def test_cutover_rolls_back_if_machine_evidence_not_recognized(monkeypatch, tmp_path):
    spec, install, compose, challenge, machine = _test_config(tmp_path)
    monkeypatch.setattr(
        "apps.gateway.accessproof_gateway.cutover_cli._docker_compose_json",
        lambda *args: compose,
    )
    commands = []
    def runner(command):
        commands.append(command)
    monkeypatch.setattr(
        "apps.gateway.accessproof_gateway.cutover_cli._collect_response",
        lambda *args, **kwargs: (
            {"http_status": 200, "response_sha256": "a" * 64,
             "decision_id": "synthetic-allowed"}
            if kwargs["allowed"] else {
                "http_status": 403 if kwargs["request_id"].endswith("-deny") else 503,
                "response_sha256": "b" * 64,
                "reason_code": ("NO_AUTHORIZED_RESOURCES" if kwargs["request_id"].endswith("-deny")
                                else "SOURCE_CONTENT_ATTESTATION_FAILED"),
            }
        ),
    )
    def server(req):
        if req.method == "GET":
            return httpx.Response(200, json={
                "state": "tested", "guard_id": machine["guard_id"],
                "application_id": spec.application_id,
                "deployment_sha256": install["deployment_sha256"],
                "route_sha256": install["route_sha256"],
            })
        return httpx.Response(409, json={"detail": {"code": "CUTOVER_AUDIT_MISSING"}})
    with httpx.Client(base_url="http://127.0.0.1:8000",
                      transport=httpx.MockTransport(server)) as client:
        with pytest.raises(CutoverError, match="stopped fail closed"):
            approved_reference_cutover(
                install=install, spec=spec, machine=machine,
                challenge_file=challenge,
                application_url="http://127.0.0.1:18155/v1/chat/completions",
                client=client, runner=runner,
                audit_wait_attempts=1, audit_wait_seconds=0,
            )
    assert len(commands) == 2
    assert commands[0].count("-f") == 2
    assert commands[1].count("-f") == 2
    assert commands[1][-4:] == ["stop", "-t", "10", "customer-rag"]
