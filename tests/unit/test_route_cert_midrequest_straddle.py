"""A dropped route connection must not end the mid-request Layer 2 observation
(2026-11-08: crossserver-langchain went UNOBSERVABLE after a tunnel reset)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/live/remote_route_certification.py"


@pytest.fixture(scope="module")
def cert():
    spec = importlib.util.spec_from_file_location("ap_remote_route_cert_script", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


FIN = "finance_alice.txt"
ALLOW = [{"layer": "layer1", "result": "allow"}]
DENY = [{"layer": "layer1", "result": "deny"}]


def test_transport_failure_without_guard_evidence_is_retried(cert):
    s = {"detail": "ROUTE_UNREACHABLE:URLError", "model_calls": 0, "model_context_documents": []}
    assert cert.straddle_next_step([], False, s, FIN) == "retry_transport"


def test_layer1_exclusion_evidence_stops_search(cert):
    s = {"detail": None, "model_calls": 0, "model_context_documents": []}
    assert cert.straddle_next_step(DENY, False, s, FIN) == "stop"
    s = {"model_calls": 1, "model_context_documents": ["other.txt"]}
    assert cert.straddle_next_step(ALLOW, True, s, FIN) == "stop"


def test_admitted_without_flip_keeps_searching(cert):
    # Observed attempt 1: admitted, Guard not yet flipped, response dropped by tunnel.
    s = {"detail": "ROUTE_UNREACHABLE:RemoteDisconnected", "model_calls": 1, "model_context_documents": [FIN]}
    assert cert.straddle_next_step(ALLOW, True, s, FIN) == "continue"


def test_unobservable_still_never_certifies(cert):
    """The straddle helper cannot produce PASS: an unobserved check still blocks."""
    from apps.gateway.accessproof_gateway import remote_route_certification as rrc
    assert "MIDREQUEST_LAYER2_BLOCKED" in rrc.REQUIRED_CHECKS


def test_positive_requests_retry_only_fail_closed_non_decisions(cert):
    # 2026-11-08 pilot: the first allowed question hit a transient Guard 503.
    assert cert.positive_request_retryable({"http_status": 503, "detail": "GUARD_REQUEST_FAILED"})
    assert cert.positive_request_retryable({"http_status": 503, "detail": "AUTHORIZATION_REVISION_CHANGED"})
    assert cert.positive_request_retryable({"http_status": None, "detail": "ROUTE_UNREACHABLE:URLError"})
    # A real answer, a policy denial or identity rejection is final.
    assert not cert.positive_request_retryable({"http_status": 200, "detail": None})
    assert not cert.positive_request_retryable({"http_status": 403, "detail": "GUARD_POLICY_DENIED"})
    assert not cert.positive_request_retryable({"http_status": 401, "detail": "IDENTITY_REJECTED"})


def test_hold_flip_requires_explicit_deny_in_source(cert):
    import inspect
    src = inspect.getsource(cert.run_revocation)
    assert 'if d == "DENY":' in src and "unavailable_during_hold" in src
    # an ambiguous block never becomes PASS: PASS still needs a revocation reason + gateway audit
    assert 'l2[-1]["reason"] in REVOCATION_REASONS and gw' in src
