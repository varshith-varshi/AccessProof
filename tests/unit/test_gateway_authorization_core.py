import httpx

from packages.rag_core import GuardClient, ProtectedRAG, RetrievedResource


def test_protected_rag_buffers_model_output_until_layer2_allows() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("filter-resources"):
            return httpx.Response(200, json={"decision_id": "d1", "decision": "allow", "allowed": [{"source_id": "drive", "resource_id": "H456"}], "denied": [], "unknown": []})
        return httpx.Response(200, json={"decision": "allow", "reason": "TRUSTED_PROVENANCE_VALID"})

    client = GuardClient("https://guard.example", client=httpx.Client(transport=httpx.MockTransport(handler)))
    rag = ProtectedRAG(client, allow_unattested_metadata=True)
    released: list[str] = []

    def model(resources):
        assert [item.resource_id for item in resources] == ["H456"]
        yield "leave "
        yield "policy"

    response = rag.run(employee_token="employee", application_id="rag", request_id="r1", retrieved=[RetrievedResource("drive", "H456", "chunk-1")], generate=model, source_trace=lambda: [RetrievedResource("drive", "H456", "chunk-1")])
    assert response.response == "leave policy"
    assert response.decision == "allow"
    assert len(requests) == 2
    assert released == []


def test_guard_health_is_typed_without_sending_identity_data() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"status": "ok", "policy_version": 7, "ready": True})

    client = GuardClient("https://guard.example", client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert client.health() == {"status": "ok", "policy_version": 7, "ready": True}
    assert requests[0].url.path == "/health"
    assert "authorization" not in requests[0].headers


def test_protected_rag_releases_zero_model_output_when_layer2_blocks() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if request.url.path.endswith("filter-resources"):
            return httpx.Response(200, json={"decision_id": "d1", "decision": "allow", "allowed": [{"source_id": "drive", "resource_id": "H456"}], "denied": [], "unknown": []})
        return httpx.Response(200, json={"decision": "block", "reason": "PROVENANCE_ESCAPE"})

    guard = GuardClient("https://guard.example", client=httpx.Client(transport=httpx.MockTransport(handler)))
    response = ProtectedRAG(guard, allow_unattested_metadata=True).run(employee_token="employee", application_id="rag", request_id="r1", retrieved=[RetrievedResource("drive", "H456")], generate=lambda _: ["secret", " output"], source_trace=lambda: [RetrievedResource("drive", "H456")])
    assert response.response is None
    assert response.reason == "PROVENANCE_ESCAPE"
    assert calls == 2


def test_protected_rag_reports_no_authorized_resources_for_a_protect_denial() -> None:
    """A valid Protect-mode deny is not an adapter mode mismatch."""
    model_called = False

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("filter-resources")
        return httpx.Response(200, json={
            "decision_id": "revoked", "decision": "block", "mode": "protect",
            "allowed": [], "denied": [{"source_id": "drive", "resource_id": "H456"}],
            "unknown": [],
        })

    guard = GuardClient("https://guard.example", client=httpx.Client(
        transport=httpx.MockTransport(handler)
    ))

    def model(_: list[RetrievedResource]) -> str:
        nonlocal model_called
        model_called = True
        return "must never run"

    result = ProtectedRAG(guard, allow_unattested_metadata=True).run(
        employee_token="employee", application_id="rag", request_id="revoked-request",
        retrieved=[RetrievedResource("drive", "H456")], generate=model,
    )
    assert result.decision == "block"
    assert result.response is None
    assert result.reason == "NO_AUTHORIZED_RESOURCES"
    assert not model_called


def test_layer1_chunk_allowlist_cannot_expose_another_chunk_of_same_document() -> None:
    """An explicit chunk allow must be treated as narrower than file access.

    This is a regression for a future chunk-scoped source policy: before the
    fix, SDK matching used only ``(source_id, resource_id)`` and passed both
    chunks of a file into the model context.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("filter-resources"):
            return httpx.Response(200, json={
                "decision_id": "d1", "decision": "allow",
                "allowed": [{
                    "source_id": "drive", "resource_id": "finance",
                    "chunk_ids": ["approved-chunk"],
                }],
                "denied": [], "unknown": [],
            })
        return httpx.Response(200, json={"decision": "allow", "reason": "OK"})

    seen: list[str] = []
    guard = GuardClient("https://guard.example", client=httpx.Client(
        transport=httpx.MockTransport(handler)
    ))
    result = ProtectedRAG(guard, allow_unattested_metadata=True).run(
        employee_token="synthetic-employee", application_id="rag", request_id="chunk-scope",
        retrieved=[
            RetrievedResource("drive", "finance", "approved-chunk", "safe context"),
            RetrievedResource("drive", "finance", "forbidden-chunk", "FINANCE_CANARY"),
        ],
        generate=lambda resources: (seen.extend(item.content for item in resources) or "safe answer"),
        source_trace=lambda: [RetrievedResource("drive", "finance", "approved-chunk")],
    )
    assert result.decision == "allow"
    assert result.response == "safe answer"
    assert seen == ["safe context"]
