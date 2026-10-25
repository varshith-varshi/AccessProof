from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from apps.api.accessproof_api.rag_challenge_verifier import (
    request_ids, verify_reference_evidence,
)


NONCE = "nonce-for-synthetic-reference-testing-0123456"
IDS = request_ids(NONCE)


def _event(name: str, layer: str, result: str, reason: str, *, decision: str,
           subject: str = "alice", policy: int = 7):
    return SimpleNamespace(
        request_id=IDS[name], layer=layer, result=result, reason=reason,
        decision_id=decision, subject_id=subject, policy_version=policy,
    )


def _evidence():
    events = [
        _event("allow", "layer1", "allow", "LAYER1_EFFECTIVE_ACCESS", decision="positive"),
        _event("allow", "layer2", "allow", "TRUSTED_PROVENANCE_VALID", decision="positive"),
        _event("deny", "layer1", "block", "LAYER1_EFFECTIVE_ACCESS", decision="negative", subject="bob"),
        _event("tamper", "layer1", "allow", "LAYER1_EFFECTIVE_ACCESS", decision="forgery"),
        _event("layer2_revoke", "layer1", "allow", "LAYER1_EFFECTIVE_ACCESS", decision="revoke"),
        _event("layer2_revoke", "layer2", "block", "LAYER2_ACCESS_REVOKED", decision="revoke"),
    ]
    observations = []
    for name in ("allow", "deny", "tamper", "layer2_revoke"):
        observations.append({
            "name": name, "request_id": IDS[name],
            "http_status": {"allow": 200, "deny": 403, "tamper": 503, "layer2_revoke": 403}[name],
            "response_sha256": "1" * 64,
            "response_byte_count": 79,
            "forbidden_content_observed": False,
            "reason_code": {
                "allow": None, "deny": "NO_AUTHORIZED_RESOURCES",
                "tamper": "SOURCE_CONTENT_ATTESTATION_FAILED",
                "layer2_revoke": "LAYER2_ACCESS_REVOKED",
            }[name],
            "decision": "allow" if name == "allow" else None,
            "decision_id": "positive" if name == "allow" else None,
        })
    return observations, events


def _check(observations, events, *, nonce=NONCE, version=7):
    return verify_reference_evidence(
        nonce=nonce, observations=observations, guard_events=events,
        source_id="source-1", guard_policy_version=version,
    )


def test_machine_evidence_is_not_accepted_without_real_layer1_layer2_audits():
    obs, events = _evidence()
    assert _check(obs, events) == (True, "REFERENCE_ROUTE_CHALLENGES_VERIFIED")
    assert _check(obs, [])[0] is False
    assert _check(obs, events[:-1])[0] is False


@pytest.mark.parametrize("change", [
    ("name", "unknown"), ("http_status", 200),
    ("response_sha256", "xyz"), ("response_byte_count", -1),
    ("forbidden_content_observed", True), ("reason_code", "GUARD_UNAVAILABLE"),
])
def test_forged_denial_observation_fails_closed(change):
    obs, events = _evidence()
    key, value = change
    obs[1] = {**obs[1], key: value}
    assert _check(obs, events)[0] is False


def test_wrong_nonce_replay_shadow_and_policy_rollover_fail_closed():
    obs, events = _evidence()
    assert _check(obs, events, nonce="invalid-new-nonce-aaaaaaaaaaaaaaaa")[0] is False
    assert _check(obs, events, version=1)[0] is False
    events[0] = replace(events[0], result="would_allow") if hasattr(events[0], "__dataclass_fields__") else SimpleNamespace(
        **{**vars(events[0]), "result": "would_allow"}
    )
    assert _check(obs, events)[0] is False


def test_guard_layer2_must_match_layer1_subject_and_decision():
    obs, events = _evidence()
    events[-1] = SimpleNamespace(**{**vars(events[-1]), "subject_id": "other"})
    assert _check(obs, events)[0] is False
    obs, events = _evidence()
    events[1] = SimpleNamespace(**{**vars(events[1]), "decision_id": "forged"})
    assert _check(obs, events)[0] is False
