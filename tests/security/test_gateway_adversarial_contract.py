"""Adversarial SDK / Guard contract tests using synthetic HTTP responses only."""
from __future__ import annotations

import httpx
import pytest

from packages.rag_core.protection import GuardClient, ProtectedRAG, RetrievedResource

PUBLIC = RetrievedResource("src-alpha", "public", content="visible")
CANARY = "PRIVATE_CANARY_FROM_BETA_NEVER_SEND"


def _harness(*, layer1_decision="allow", layer1_mode="protect",
             layer2_decision="allow", layer2_reason="VALID", status=200,
             second_filter=None):
    calls = []
    def handle(request):
        calls.append(request)
        if request.url.path.endswith("/filter-resources"):
            if second_filter is not None and sum(
                r.url.path.endswith("/filter-resources") for r in calls
            ) > 1:
                return httpx.Response(200, json=second_filter)
            return httpx.Response(200, json={
                "decision_id": "d1", "decision": layer1_decision, "mode": layer1_mode,
                "allowed": [{"source_id": "src-alpha", "resource_id": "public"}],
            })
        return httpx.Response(status, json={
            "decision": layer2_decision, "reason": layer2_reason,
        })
    return ProtectedRAG(GuardClient(
        "https://synthetic-guard.invalid",
        client=httpx.Client(transport=httpx.MockTransport(handle))
    ), allow_unattested_metadata=True), calls


def test_protect_layer1_must_not_release_if_layer2_silently_reverts_to_shadow():
    rag, calls = _harness(layer1_mode="protect", layer2_decision="would_block",
                          layer2_reason="UNVERIFIED")
    answer = rag.run(employee_token="synthetic", application_id="app",
                     retrieved=[PUBLIC], generate=lambda _: [CANARY], source_trace=lambda: [PUBLIC])
    assert len(calls) == 2
    assert answer.decision == "block"
    assert answer.response is None


def test_protect_layer1_must_not_accept_would_allow_at_layer2():
    rag, calls = _harness(layer1_mode="protect", layer2_decision="would_allow")
    answer = rag.run(employee_token="synthetic", application_id="app",
                     retrieved=[PUBLIC], generate=lambda _: CANARY, source_trace=lambda: [PUBLIC])
    assert len(calls) == 2
    assert answer.decision == "block"
    assert answer.response is None


@pytest.mark.parametrize(("code", "reason"), [
    (401, "IDENTITY_REJECTED"), (403, "GUARD_POLICY_DENIED"),
    (429, "GUARD_REQUEST_FAILED"), (500, "GUARD_REQUEST_FAILED"), (503, "GUARD_REQUEST_FAILED"),
])
def test_guard_post_generation_http_error_is_an_explicit_safe_block(code, reason):
    rag, calls = _harness(status=code)
    answer = rag.run(employee_token="synthetic", application_id="app",
                     retrieved=[PUBLIC], generate=lambda _: CANARY, source_trace=lambda: [PUBLIC])
    assert len(calls) == 2
    assert answer.decision == "block"
    assert answer.response is None
    # D-20: still blocked, but identity/policy refusals are not reported as outages.
    assert answer.reason == reason


def test_invalid_guard_json_fails_closed():
    def respond(request):
        if request.url.path.endswith("/filter-resources"):
            return httpx.Response(200, json={
                "decision_id": "d1", "decision": "allow",
                "allowed": [{"source_id": "src-alpha", "resource_id": "public"}],
            })
        return httpx.Response(200, text="not valid JSON")
    rag = ProtectedRAG(GuardClient("https://guard.invalid",
        client=httpx.Client(transport=httpx.MockTransport(respond))),
        allow_unattested_metadata=True)
    answer = rag.run(employee_token="synthetic", application_id="app",
                     retrieved=[PUBLIC], generate=lambda _: CANARY, source_trace=lambda: [PUBLIC])
    assert answer.decision == "block"
    assert answer.response is None


def test_stream_generator_exception_is_safe_block():
    rag, calls = _harness()
    def broken_model(_):
        yield CANARY[:8]
        raise RuntimeError("synthetic generator interruption")
    answer = rag.run(employee_token="synthetic", application_id="app",
                     retrieved=[PUBLIC], generate=broken_model)
    assert answer.decision == "block"
    assert answer.response is None
    assert len(calls) == 1


def test_shadow_remains_observational_if_intentionally_chosen():
    rag, calls = _harness(layer1_decision="would_block",
                          layer1_mode="shadow", layer2_decision="would_block")
    answer = rag.run(employee_token="synthetic", application_id="app",
                     retrieved=[PUBLIC], generate=lambda _: "public data")
    assert answer.decision == "would_block"
    assert answer.response == "public data"
    assert len(calls) == 2


@pytest.mark.parametrize("retry_mode,retry_decision", [
    ("shadow", "would_block"),
    ("protect", "would_block"),
])
def test_protect_regeneration_must_not_release_after_downgraded_retry(
    retry_mode, retry_decision,
):
    """Each regeneration must retain Protect and pass an independent Layer 2 allow."""
    call_counts = {"filter": 0, "check": 0}

    def respond(request):
        if request.url.path.endswith("/filter-resources"):
            call_counts["filter"] += 1
            if call_counts["filter"] == 1:
                decision, mode = "allow", "protect"
            else:
                decision, mode = retry_decision, retry_mode
            return httpx.Response(200, json={
                "decision_id": f"d{call_counts['filter']}",
                "decision": decision, "mode": mode,
                "allowed": [{"source_id": "src-alpha", "resource_id": "public"}],
            })
        call_counts["check"] += 1
        if call_counts["check"] == 1:
            return httpx.Response(200, json={
                "decision": "block", "reason": "PROVENANCE_NOT_APPROVED"
            })
        return httpx.Response(200, json={
            "decision": "would_allow", "reason": "SHADOW_ONLY"
        })

    rag = ProtectedRAG(GuardClient(
        "https://synthetic-guard.invalid",
        client=httpx.Client(transport=httpx.MockTransport(respond)),
    ), allow_unattested_metadata=True)
    answer = rag.run(employee_token="synthetic", application_id="app",
                     retrieved=[PUBLIC], generate=lambda _: "safe draft",
                     regenerate=lambda _: CANARY, source_trace=lambda: [PUBLIC])
    assert answer.decision == "block"
    assert answer.response is None
