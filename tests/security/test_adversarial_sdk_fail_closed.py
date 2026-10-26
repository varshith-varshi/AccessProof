"""Untrusted retrieval metadata must not throw past the enforcement adapter."""
from packages.rag_sdk.adapters import RAGAdapter
from packages.rag_sdk.protection import ProtectedRAG


class NoNetworkGuard:
    def filter_resources(self, **kwargs):
        raise AssertionError("Malformed docs must not invoke Guard")

    def check_output(self, **kwargs):
        raise AssertionError("Malformed docs must not invoke Guard")


def test_rag_adapter_fails_closed_on_document_missing_provenance():
    adapter = RAGAdapter(ProtectedRAG(NoNetworkGuard()), source_id="synthetic-source")
    result = adapter.run(
        employee_token="synthetic", application_id="synthetic",
        documents=[{"page_content": "CONFIDENTIAL", "metadata": {}}],
        generate=lambda _allowed: "CONFIDENTIAL",
    )
    assert result.decision == "block"
    assert result.response is None
    assert result.reason == "RESOURCE_METADATA_REQUIRED"
