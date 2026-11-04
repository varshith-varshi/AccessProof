from __future__ import annotations

import json

import httpx
import pytest

from apps.gateway.accessproof_gateway.challenge_agent import (
    GatewayRouteChallenge, Probe, RouteChallengeError,
)


def _config() -> GatewayRouteChallenge:
    return GatewayRouteChallenge(
        url="http://127.0.0.1:8989/v1/chat/completions",
        application_id="reference-app", challenge_nonce="n" * 32,
        forbidden_canary="PRIVATE_SECRET_123", allowed_canary="SAFE_PUBLIC_RESULT",
        probes=tuple(Probe(
            name=name, employee_token=f"synthetic-{name}",
            retrieved_resources=[{"source_id": "drive", "resource_id": "document"}],
            expect_status={"allow": (200,), "deny": (403,), "tamper": (503,), "layer2_revoke": (403,)}[name],
            must_contain="SAFE_PUBLIC_RESULT" if name == "allow" else "",
        ) for name in ("allow", "deny", "tamper", "layer2_revoke")),
    )


def test_route_agent_observes_real_http_bodies_but_does_not_fake_production_certificate() -> None:
    requests = []
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health/ready":
            return httpx.Response(200, json={"status": "ok"})
        data = json.loads(request.content)
        requests.append(data)
        case = data["request_id"].rsplit("-", 1)[-1]
        if case == "allow":
            return httpx.Response(200, json={
                "answer": "SAFE_PUBLIC_RESULT",
                "accessproof": {"decision": "allow", "decision_id": "decision-1"},
            })
        failures = {
            "deny": (403, "NO_AUTHORIZED_RESOURCES"),
            "tamper": (503, "SOURCE_CONTENT_ATTESTATION_FAILED"),
            "layer2_revoke": (403, "LAYER2_ACCESS_REVOKED"),
        }
        status, reason = failures[case]
        return httpx.Response(status, json={"detail": {"code": reason}})
    client = httpx.Client(transport=httpx.MockTransport(respond), base_url="http://127.0.0.1:8989")
    evidence = _config().run(client=client)
    assert evidence["status"] == "PASS_LOCAL_REFERENCE_ONLY"
    assert evidence["production_certification"] is False
    assert len(evidence["probes"]) == 4
    assert len(requests) == 4
    assert all(r["request_id"].startswith("ap-challenge-") for r in requests)


def test_route_agent_rejects_response_canary_leak() -> None:
    def unsafe(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health/ready":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(200, json={
            "answer": "PRIVATE_SECRET_123",
            "accessproof": {"decision": "allow", "decision_id": "decision-1"},
        })
    client = httpx.Client(transport=httpx.MockTransport(unsafe), base_url="http://127.0.0.1:8989")
    with pytest.raises(RouteChallengeError, match="unauthorized canary"):
        _config().run(client=client)


def test_route_agent_refuses_network_target_outside_loopback() -> None:
    from dataclasses import replace
    with pytest.raises(RouteChallengeError, match="loopback"):
        replace(_config(), url="http://169.254.169.254/v1/chat/completions")


def test_route_agent_enforces_strict_case_set() -> None:
    from dataclasses import replace
    with pytest.raises(RouteChallengeError, match="mandatory"):
        replace(_config(), probes=(_config().probes[0],))


def test_route_agent_rejects_unexpected_safe_status_on_denial() -> None:
    def permissive(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health/ready":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(200, json={"answer": "SAFE_PUBLIC_RESULT",
            "accessproof": {"decision": "allow", "decision_id": "decision-1"}})
    client = httpx.Client(transport=httpx.MockTransport(permissive), base_url="http://127.0.0.1:8989")
    with pytest.raises(RouteChallengeError, match="unexpected status"):
        _config().run(client=client)


def test_route_agent_refuses_false_denial_evidence_when_guard_is_unavailable() -> None:
    client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(503, json={"detail": "GUARD_UNAVAILABLE"})
    ), base_url="http://127.0.0.1:8989")
    with pytest.raises(RouteChallengeError, match="not ready"):
        _config().run(client=client)


def _revocation_config(revoke_status=(403, 503), timeout=60.0) -> GatewayRouteChallenge:
    from dataclasses import replace
    base = _config()
    probes = tuple(replace(p, expect_status=revoke_status) if p.name == "layer2_revoke" else p for p in base.probes)
    return replace(base, probes=probes, timeout_seconds=timeout)


def _responder(revoke):
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health/ready":
            return httpx.Response(200, json={"status": "ok"})
        case = json.loads(request.content)["request_id"].rsplit("-", 1)[-1]
        if case == "allow":
            return httpx.Response(200, json={"answer": "SAFE_PUBLIC_RESULT",
                                             "accessproof": {"decision": "allow", "decision_id": "d"}})
        status, reason = {"deny": (403, "NO_AUTHORIZED_RESOURCES"),
                          "tamper": (503, "SOURCE_CONTENT_ATTESTATION_FAILED"), "layer2_revoke": revoke}[case]
        return httpx.Response(status, json={"detail": {"code": reason}})
    return respond


def test_d26_revision_changed_layer2_block_is_an_accepted_revoke_outcome() -> None:
    client = httpx.Client(transport=httpx.MockTransport(_responder((503, "AUTHORIZATION_REVISION_CHANGED"))),
                          base_url="http://127.0.0.1:8989")
    assert _revocation_config().run(client=client)["status"] == "PASS_LOCAL_REFERENCE_ONLY"


@pytest.mark.parametrize("revoke", [(503, "LAYER2_ACCESS_REVOKED"), (403, "AUTHORIZATION_REVISION_CHANGED"),
                                    (503, "GUARD_UNAVAILABLE")])
def test_d26_mismatched_or_generic_revoke_outcomes_are_rejected(revoke) -> None:
    client = httpx.Client(transport=httpx.MockTransport(_responder(revoke)), base_url="http://127.0.0.1:8989")
    with pytest.raises(RouteChallengeError):
        _revocation_config().run(client=client)


@pytest.mark.parametrize("bad", [{"revoke_status": (200,)}, {"timeout": 0.5}, {"timeout": 600}])
def test_d26_revoke_status_and_timeout_are_bounded(bad) -> None:
    with pytest.raises(RouteChallengeError):
        _revocation_config(**{"revoke_status": (403, 503), "timeout": 60.0, **bad})
