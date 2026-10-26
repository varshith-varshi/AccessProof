import httpx
import pytest

from packages.rag_sdk import (
    AdapterConfigurationError,
    LangChainAdapter,
    LlamaIndexAdapter,
    ProtectedRAG,
    GuardClient,
    RetrievedResource,
    normalize_document,
)


class FakeLangChainDocument:
    def __init__(self, text: str, metadata: dict[str, str]) -> None:
        self.page_content = text
        self.metadata = metadata


class FakeLlamaNode:
    def __init__(self, text: str, metadata: dict[str, str]) -> None:
        self._text = text
        self.metadata = metadata

    def get_content(self) -> str:
        return self._text


def _guard(*, allowed: list[dict[str, str]], layer2: str = "allow") -> GuardClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("filter-resources"):
            return httpx.Response(200, json={"decision_id": "d1", "decision": "allow", "allowed": allowed, "denied": [], "unknown": []})
        return httpx.Response(200, json={"decision": layer2, "reason": "TEST"})

    return GuardClient("https://guard.example", client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_normalize_requires_stable_source_and_resource_ids() -> None:
    with pytest.raises(AdapterConfigurationError, match="stable resource_id"):
        normalize_document({"page_content": "secret", "metadata": {"source_id": "drive"}})


def test_langchain_adapter_passes_only_layer1_authorized_documents_to_generator() -> None:
    docs = [
        FakeLangChainDocument("allowed", {"source_id": "drive", "resource_id": "a", "chunk_id": "a1"}),
        FakeLangChainDocument("secret", {"source_id": "drive", "resource_id": "b", "chunk_id": "b1"}),
    ]
    guard = _guard(allowed=[{"source_id": "drive", "resource_id": "a", "chunk_ids": ["a1"]}])
    seen: list[list[str]] = []
    response = LangChainAdapter(ProtectedRAG(guard, allow_unattested_metadata=True)).run(
        employee_token="verified-token",
        application_id="rag",
        documents=docs,
        generate=lambda authorized: (seen.append([doc.page_content for doc in authorized]) or "safe"),
        source_trace=lambda: [RetrievedResource("drive", "a", "a1")],
    )
    assert response.response == "safe"
    assert seen == [["allowed"]]


def test_llamaindex_adapter_blocks_before_release_when_layer2_rejects() -> None:
    node = FakeLlamaNode("secret", {"source_id": "drive", "document_id": "doc-1", "node_id": "n-1"})
    guard = _guard(allowed=[{"source_id": "drive", "resource_id": "doc-1", "chunk_ids": ["n-1"]}], layer2="block")
    generated = False

    def generate(_: list[FakeLlamaNode]) -> str:
        nonlocal generated
        generated = True
        return "secret"

    response = LlamaIndexAdapter(ProtectedRAG(guard, allow_unattested_metadata=True)).run(
        employee_token="verified-token", application_id="rag", documents=[node], generate=generate,
        source_trace=lambda: [RetrievedResource("drive", "doc-1", "n-1")]
    )
    assert generated is True
    assert response.response is None
    assert response.decision == "block"

