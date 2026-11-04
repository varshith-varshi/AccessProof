"""Machine-observed RAG challenge corroboration with Guard-audited decisions.

This is intentionally specific to the signed-manifest Gateway reference
contract. It does not certify arbitrary RAG paths or independently verify an
arbitrary customer's application ingress/egress topology.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any, Iterable

NAMES = ("allow", "deny", "tamper", "layer2_revoke")
EXPECTED_HTTP = {"allow": 200, "deny": 403, "tamper": 503, "layer2_revoke": 403}
EXPECTED_REASON = {
    "deny": "NO_AUTHORIZED_RESOURCES",
    "tamper": "SOURCE_CONTENT_ATTESTATION_FAILED",
    "layer2_revoke": "LAYER2_ACCESS_REVOKED",
}
# D-26: a Guard with authorization revisions reports an access change between
# Layer 1 and Layer 2 as AUTHORIZATION_REVISION_CHANGED (Gateway 503) because
# the revision check precedes the per-decision recheck. Both are a Guard-audited
# Layer 2 block of a post-Layer-1 authorization change; each outcome must still
# agree with the Guard's own audited Layer 2 reason (see verify_reference_evidence).
LAYER2_REVOKE_OUTCOMES = {
    (403, "LAYER2_ACCESS_REVOKED"),
    (503, "AUTHORIZATION_REVISION_CHANGED"),
}
_HEX = re.compile(r"^[0-9a-f]{64}$")


def request_ids(nonce: str) -> dict[str, str]:
    prefix = "ap-challenge-" + hashlib.sha256(nonce.encode("utf-8")).hexdigest()[:24]
    return {name: f"{prefix}-{name}" for name in NAMES}


def verify_reference_evidence(
    *, nonce: str, observations: list[dict[str, Any]],
    guard_events: Iterable[Any],
    source_id: str, guard_policy_version: int,
) -> tuple[bool, str]:
    """Verify correlation to Guard machine audit records and HTTP outcomes.

    Caller must authenticate the enrolled Guard, check nonce freshness/replay,
    tenant/application/Guard bindings, configuration fingerprint and approved
    deployment hashes before calling this function.
    """
    if not source_id or guard_policy_version < 1:
        return False, "GUARD_POLICY_UNAVAILABLE"
    if len(observations) != 4:
        return False, "MISSING_CHALLENGES"
    expected_ids = request_ids(nonce)
    recorded = {}
    for item in observations:
        if not isinstance(item, dict):
            return False, "INVALID_CHALLENGE_OBSERVATION"
        name = item.get("name")
        if not isinstance(name, str) or name not in expected_ids or name in recorded:
            return False, "DUPLICATE_OR_UNKNOWN_CHALLENGE"
        if item.get("request_id") != expected_ids[name]:
            return False, "CHALLENGE_REQUEST_OR_STATUS_MISMATCH"
        if name == "layer2_revoke":
            if (item.get("http_status"), item.get("reason_code")) not in LAYER2_REVOKE_OUTCOMES:
                return False, "CHALLENGE_REQUEST_OR_STATUS_MISMATCH"
        elif item.get("http_status") != EXPECTED_HTTP[name]:
            return False, "CHALLENGE_REQUEST_OR_STATUS_MISMATCH"
        if (not isinstance(item.get("response_sha256"), str)
                or not _HEX.fullmatch(item["response_sha256"])
                or type(item.get("response_byte_count")) is not int
                or not 0 < item["response_byte_count"] <= 1_000_000
                or item.get("forbidden_content_observed") is not False):
            return False, "INVALID_RESPONSE_BYTE_EVIDENCE"
        if name not in {"allow", "layer2_revoke"} and item.get("reason_code") != EXPECTED_REASON[name]:
            return False, "UNVERIFIED_DENIAL_REASON"
        if name == "allow" and (item.get("decision") != "allow"
                                or not isinstance(item.get("decision_id"), str)
                                or not item["decision_id"]):
            return False, "MISSING_POSITIVE_GUARD_DECISION"
        recorded[name] = item
    if set(recorded) != set(NAMES):
        return False, "MISSING_CHALLENGES"
    by_request: dict[str, list[Any]] = defaultdict(list)
    for event in guard_events:
        if getattr(event, "request_id", None) in expected_ids.values():
            if (int(getattr(event, "policy_version", 0) or 0) < 1
                    or int(event.policy_version) > guard_policy_version):
                return False, "INCONSISTENT_GUARD_POLICY"
            # Protect-only challenge decisions. Shadow allows cannot count.
            if event.result not in {"allow", "block"}:
                return False, "SHADOW_AUDIT_NOT_ACCEPTED"
            by_request[event.request_id].append(event)
    if not all(by_request.get(request_id) for request_id in expected_ids.values()):
        return False, "GUARD_AUDIT_EVIDENCE_MISSING"
    # D-29: the Guard uploads audits asynchronously; the Layer 2 record of a held
    # response is written only when that response returns. A request that MUST
    # have Layer 2 evidence but has none uploaded yet is "not yet delivered"
    # (retryable), not a failed proof. A present but wrong record still fails.
    for name in ("allow", "layer2_revoke"):
        if not any(event.layer == "layer2" for event in by_request[expected_ids[name]]):
            return False, "GUARD_AUDIT_EVIDENCE_MISSING"

    def get(name: str, layer: str, result: str, reason: str | None = None) -> list[Any]:
        return [event for event in by_request[expected_ids[name]]
                if event.layer == layer and event.result == result
                and (reason is None or event.reason == reason)]

    def bound(events_l1: list[Any], events_l2: list[Any]) -> bool:
        return any(
            a.decision_id and a.decision_id == b.decision_id
            and a.subject_id == b.subject_id
            for a in events_l1 for b in events_l2
        )

    if not bound(get("allow", "layer1", "allow"),
                 get("allow", "layer2", "allow", "TRUSTED_PROVENANCE_VALID")):
        return False, "POSITIVE_GUARD_LAYERS_NOT_MATCHED"
    if not any(event.decision_id == recorded["allow"]["decision_id"]
               for event in get("allow", "layer1", "allow")):
        return False, "POSITIVE_DECISION_ID_MISMATCH"
    if not get("deny", "layer1", "block"):
        return False, "DENIAL_NOT_GUARD_AUDITED"
    if not get("tamper", "layer1", "allow") or any(
        event.layer == "layer2" and event.result == "allow"
        for event in by_request[expected_ids["tamper"]]
    ):
        return False, "ATTESTATION_FAILURE_NOT_CONFIRMED"
    if not bound(get("layer2_revoke", "layer1", "allow"),
                 get("layer2_revoke", "layer2", "block", recorded["layer2_revoke"]["reason_code"])):
        return False, "REVOKE_NOT_BLOCKED_IN_LAYER2"
    # Correlate only uploaded Guard records. The customer deployment's
    # complete egress topology still needs a separately measured check.
    return True, "REFERENCE_ROUTE_CHALLENGES_VERIFIED"
