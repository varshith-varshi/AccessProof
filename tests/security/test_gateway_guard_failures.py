"""Guard failures must produce explicit denial without publishing model bytes."""
import httpx
import pytest

from packages.rag_core import GuardClient, ProtectedRAG, RetrievedResource


@pytest.mark.parametrize("failure_stage", ["layer1", "late-source", "layer2"])
def test_guard_error_produces_safe_block_and_no_response(failure_stage):
    calls = []
    canary = "SYNTHETIC_LOCAL_FORBIDDEN_CANARY"

    def handler(request):
        calls.append(request.url.path)
        if request.url.path.endswith("/filter-resources"):
            if failure_stage == "layer1" or (
                failure_stage == "late-source" and calls.count(request.url.path) == 2
            ):
                return httpx.Response(403, json={"detail": "APPLICATION_SOURCE_MISMATCH"})
            return httpx.Response(200, json={
                "decision_id": f"decision-{len(calls)}", "decision": "allow",
                "allowed": [{"source_id": "drive", "resource_id": "public"}],
                "denied": [], "unknown": [],
            })
        if failure_stage == "layer2":
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        return httpx.Response(200, json={
            "decision": "allow", "reason": "TRUSTED_PROVENANCE_VALID",
        })

    guard = GuardClient("https://local.test", client=httpx.Client(
        transport=httpx.MockTransport(handler),
    ))
    seen = []
    response = ProtectedRAG(guard, allow_unattested_metadata=True).run(
        employee_token="synthetic", application_id="rag",
        retrieved=[RetrievedResource("drive", "public", content="public handbook")],
        generate=lambda resources: (seen.append(resources) or canary),
        source_trace=lambda: [
            RetrievedResource("drive", "public"),
            *([RetrievedResource("other-source", "secret")]
              if failure_stage == "late-source" else []),
        ],
    )
    assert response.decision == "block"
    assert response.response is None
    assert canary not in str(response)
    if failure_stage == "layer1":
        assert not seen
    else:
        assert len(seen) == 1


def test_healthy_guard_keeps_legitimate_answer():
    def handler(request):
        if request.url.path.endswith("/filter-resources"):
            return httpx.Response(200, json={
                "decision": "allow", "decision_id": "ok",
                "allowed": [{"source_id": "drive", "resource_id": "public"}],
            })
        return httpx.Response(200, json={
            "decision": "allow", "reason": "TRUSTED_PROVENANCE_VALID",
        })

    guard = GuardClient("https://local.test", client=httpx.Client(
        transport=httpx.MockTransport(handler),
    ))
    result = ProtectedRAG(guard, allow_unattested_metadata=True).run(
        employee_token="synthetic", application_id="rag",
        retrieved=[RetrievedResource("drive", "public", content="approved")],
        generate=lambda resources: resources[0].content,
        source_trace=lambda: [RetrievedResource("drive", "public")],
    )
    assert result.decision == "allow"
    assert result.response == "approved"
