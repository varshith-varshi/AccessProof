"""Adversarial inconsistent Guard protocol decisions must never release model output."""
from packages.rag_sdk.protection import ProtectedRAG, RetrievedResource


_ALLOWED = RetrievedResource(source_id="drive", resource_id="allowed-file", content="synthetic")


class ContradictoryGuard:
    def __init__(self, *, first_block: bool = False, late_block: bool = False):
        self.first_block = first_block
        self.late_block = late_block
        self.filter_calls = 0
        self.check_calls = 0

    def filter_resources(self, *, resources, **_):
        self.filter_calls += 1
        chosen = "block" if (self.first_block and self.filter_calls == 1) or (
            self.late_block and self.filter_calls >= 2
        ) else "allow"
        return {
            "mode": "protect", "decision_id": f"d-{self.filter_calls}",
            "decision": chosen,
            "allowed": [
                {"source_id": item.source_id,
                 "resource_id": item.resource_id,
                 "chunk_ids": [item.chunk_id] if item.chunk_id else []}
                for item in resources
            ],
        }

    def check_output(self, **_):
        self.check_calls += 1
        return {"decision": "allow", "reason": "TRUSTED_PROVENANCE_VALID"}


def test_protect_never_generates_after_layer1_block_even_if_allowlist_conflicts():
    guard = ContradictoryGuard(first_block=True)
    generated = []
    response = ProtectedRAG(guard).run(
        employee_token="synthetic", application_id="app",
        retrieved=[_ALLOWED],
        generate=lambda allowed: generated.append(allowed) or "TOP SECRET",
        source_trace=lambda: [_ALLOWED],
    )
    assert response.decision == "block"
    assert response.response is None
    assert generated == []
    assert guard.check_calls == 0


def test_protect_blocks_late_source_when_its_guard_decision_is_block():
    late = RetrievedResource(source_id="drive", resource_id="late-cache-secret")
    guard = ContradictoryGuard(late_block=True)
    response = ProtectedRAG(guard).run(
        employee_token="synthetic", application_id="app",
        retrieved=[_ALLOWED], generate=lambda allowed: "TOP SECRET",
        source_trace=lambda: [_ALLOWED, late],
    )
    assert response.decision == "block"
    assert response.response is None
    assert guard.check_calls == 0


def test_regeneration_never_runs_when_new_guard_decision_is_block():
    guard = ContradictoryGuard(late_block=True)
    regeneration = []
    original_check = guard.check_output

    def block_first_layer2(**kwargs):
        if guard.check_calls == 0:
            guard.check_calls += 1
            return {"decision": "block", "reason": "PROVENANCE_ESCAPE"}
        return original_check(**kwargs)

    guard.check_output = block_first_layer2
    response = ProtectedRAG(guard).run(
        employee_token="synthetic", application_id="app",
        retrieved=[_ALLOWED],
        generate=lambda allowed: "candidate",
        source_trace=lambda: [_ALLOWED],
        regenerate=lambda allowed: regeneration.append(allowed) or "secret",
    )
    assert response.decision == "block"
    assert response.response is None
    assert regeneration == []


def test_guard_rejects_unknown_nested_protocol_fields_before_identity_or_acl_work(tmp_path, monkeypatch):
    """Reject request-smuggling fields rather than ignoring them at the Guard."""
    from fastapi.testclient import TestClient
    from apps.guard.accessproof_guard import app as guard_app
    from apps.guard.accessproof_guard.cache import PolicyCache

    policy = PolicyCache(str(tmp_path / "strict-guard-contract.db"))
    monkeypatch.setattr(guard_app, "cache", policy)
    with TestClient(guard_app.app) as client:
        response = client.post("/guard/v1/filter-resources", json={
            "application_id": "rag", "request_id": "request",
            "resources": [{
                "source_id": "drive", "resource_id": "file",
                "untrusted_context": "PRIVATE_CANARY",
            }],
        })
    assert response.status_code == 422
