import httpx

from packages.rag_sdk import GuardClient, ProtectedRAG, RetrievedResource


def test_protected_rag_buffers_model_output_until_layer2_allows() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("filter-resources"):
            return httpx.Response(200, json={"decision_id": "d1", "decision": "allow", "allowed": [{"source_id": "drive", "resource_id": "H456"}], "denied": [], "unknown": []})
        return httpx.Response(200, json={"decision": "allow", "reason": "TRUSTED_PROVENANCE_VALID"})

    client = GuardClient("https://guard.example", client=httpx.Client(transport=httpx.MockTransport(handler)))
    rag = ProtectedRAG(client)
    released: list[str] = []

    def model(resources):
        assert [item.resource_id for item in resources] == ["H456"]
        yield "leave "
        yield "policy"

    response = rag.run(employee_token="employee", application_id="rag", request_id="r1", retrieved=[RetrievedResource("drive", "H456", "chunk-1")], generate=model)
    assert response.response == "leave policy"
    assert response.decision == "allow"
    assert len(requests) == 2
    assert released == []


def test_protected_rag_releases_zero_model_output_when_layer2_blocks() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if request.url.path.endswith("filter-resources"):
            return httpx.Response(200, json={"decision_id": "d1", "decision": "allow", "allowed": [{"source_id": "drive", "resource_id": "H456"}], "denied": [], "unknown": []})
        return httpx.Response(200, json={"decision": "block", "reason": "PROVENANCE_ESCAPE"})

    guard = GuardClient("https://guard.example", client=httpx.Client(transport=httpx.MockTransport(handler)))
    response = ProtectedRAG(guard).run(employee_token="employee", application_id="rag", request_id="r1", retrieved=[RetrievedResource("drive", "H456")], generate=lambda _: ["secret", " output"])
    assert response.response is None
    assert response.reason == "PROVENANCE_ESCAPE"
    assert calls == 2
