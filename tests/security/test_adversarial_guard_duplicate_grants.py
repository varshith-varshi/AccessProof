"""Reject contradictory grants for the same document before model input."""
import pytest

from packages.rag_core.protection import ProtectedRAG, RetrievedResource


class ContradictoryGuard:
    def __init__(self, grants):
        self.grants = grants
        self.layer2 = 0

    def filter_resources(self, **kwargs):
        return {
            "mode": "protect", "decision": "allow", "decision_id": "d1",
            "allowed": [
                {"source_id": "drive", "resource_id": "file", "chunk_ids": value}
                for value in self.grants
            ],
        }

    def check_output(self, **kwargs):
        self.layer2 += 1
        return {"decision": "allow", "reason": "SYNTHETIC"}


@pytest.mark.parametrize("grants", [
    [["public"], []],
    [[], ["public"]],
    [["public"], ["private"]],
])
def test_contradictory_chunk_allowlist_never_widens_authorization(grants):
    guard = ContradictoryGuard(grants)
    generated = []
    public = RetrievedResource("drive", "file", "public", "PUBLIC")
    private = RetrievedResource("drive", "file", "private", "PRIVATE_CANARY")
    output = ProtectedRAG(guard, allow_unattested_metadata=True).run(
        employee_token="synthetic", application_id="app",
        retrieved=[public, private],
        generate=lambda allowed: generated.extend(allowed) or "PUBLIC",
        source_trace=lambda: [public],
    )
    assert output.decision == "block"
    assert output.response is None
    assert generated == []
    assert guard.layer2 == 0


def test_redundant_identical_chunk_allowlist_keeps_authorized_positive_control():
    guard = ContradictoryGuard([["public"], ["public"]])
    public = RetrievedResource("drive", "file", "public", "PUBLIC")
    private = RetrievedResource("drive", "file", "private", "PRIVATE_CANARY")
    generated = []
    output = ProtectedRAG(guard, allow_unattested_metadata=True).run(
        employee_token="synthetic", application_id="app",
        retrieved=[public, private],
        generate=lambda allowed: generated.extend(allowed) or allowed[0].content,
        source_trace=lambda: [public],
    )
    assert output.decision == "allow"
    assert output.response == "PUBLIC"
    assert generated == [public]
