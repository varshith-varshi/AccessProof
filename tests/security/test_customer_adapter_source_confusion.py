"""Negative tests for source and provenance metadata collisions in real RAG adapters."""
from __future__ import annotations

from packages.rag_sdk.adapters import RAGAdapter, normalize_document, AdapterConfigurationError
from packages.rag_sdk.protection import ProtectedRAG, RetrievedResource

import pytest


class FakeDocument:
    def __init__(self, content: str, metadata: dict[str, str]) -> None:
        self.page_content = content
        self.metadata = metadata


class AllowingGuard:
    def __init__(self) -> None:
        self.calls = 0

    def filter_resources(self, *, resources, **kwargs):
        self.calls += 1
        return {"decision": "allow", "mode": "protect", "decision_id": "d1",
                "allowed": [{"source_id": "drive-allowed", "resource_id": "public", "chunk_ids": []}]}

    def check_output(self, **kwargs):
        return {"decision": "allow", "reason": "SYNTHETIC_TEST"}


@pytest.mark.parametrize("metadata", [
    {"source_id": "drive-private", "resource_id": "public"},
    {"accessproof_source_id": "drive-private", "resource_id": "public"},
    {"source_id": "drive-allowed", "accessproof_source_id": "drive-private", "resource_id": "public"},
])
def test_configured_source_must_never_relabel_conflicting_retrieved_documents(metadata):
    guard = AllowingGuard()
    called = []
    result = RAGAdapter(ProtectedRAG(guard, allow_unattested_metadata=True), source_id="drive-allowed").run(
        employee_token="synthetic-only", application_id="test-app",
        documents=[FakeDocument("PRIVATE_CANARY", metadata)],
        generate=lambda docs: called.append(docs) or docs[0].page_content,
        source_trace=lambda: [RetrievedResource("drive-allowed", "public")],
    )
    assert result.decision == "block"
    assert result.response is None
    assert called == []
    assert guard.calls == 0


@pytest.mark.parametrize("metadata", [
    {"source_id": "drive-allowed", "resource_id": "public", "file_id": "restricted"},
    {"source_id": "drive-allowed", "resource_id": "public", "accessproof_resource_id": "restricted"},
    {"source_id": "drive-allowed", "resource_id": "public", "chunk_id": "ok", "accessproof_chunk_id": "secret"},
])
def test_ambiguous_provider_identity_metadata_must_be_rejected(metadata):
    with pytest.raises(AdapterConfigurationError):
        normalize_document(FakeDocument("PRIVATE_CANARY", metadata))


def test_absent_source_metadata_can_use_explicit_registered_source():
    result = normalize_document(FakeDocument("PUBLIC", {"resource_id": "public"}), source_id="drive-allowed")
    assert (result.source_id, result.resource_id, result.content) == ("drive-allowed", "public", "PUBLIC")


def test_framework_document_mutation_during_guard_request_does_not_swap_model_context():
    """Shared vector/cache objects must not change between ACL check and model input."""
    source_document = FakeDocument("PUBLIC", {"source_id": "drive-allowed", "resource_id": "public"})
    seen: list[str] = []

    class ConcurrentMutationGuard(AllowingGuard):
        def filter_resources(self, *, resources, **kwargs):
            # Simulate a concurrent vector-store/cache update during Guard HTTP I/O.
            source_document.metadata["resource_id"] = "restricted"
            source_document.page_content = "PRIVATE_CANARY"
            return super().filter_resources(resources=resources, **kwargs)

    result = RAGAdapter(ProtectedRAG(ConcurrentMutationGuard(), allow_unattested_metadata=True), source_id="drive-allowed").run(
        employee_token="synthetic-only", application_id="test-app",
        documents=[source_document],
        generate=lambda docs: seen.append(docs[0].page_content) or docs[0].page_content,
        source_trace=lambda: [RetrievedResource("drive-allowed", "public")],
    )
    assert seen == ["PUBLIC"]
    assert result.response == "PUBLIC"


def test_noncopyable_retriever_document_never_leaves_unprotected_model_path():
    """If an isolated input cannot be safely made, fail closed before Guard call."""
    class Noncopyable(FakeDocument):
        def __deepcopy__(self, memo):
            raise RuntimeError("cannot snapshot untrusted object")

    guard = AllowingGuard()
    result = RAGAdapter(ProtectedRAG(guard, allow_unattested_metadata=True), source_id="drive-allowed").run(
        employee_token="synthetic-only", application_id="test-app",
        documents=[Noncopyable("PRIVATE_CANARY", {"resource_id": "public"})],
        generate=lambda docs: docs[0].page_content,
        source_trace=lambda: [RetrievedResource("drive-allowed", "public")],
    )
    assert result.decision == "block"
    assert result.response is None
    assert guard.calls == 0


def test_framework_object_returning_self_from_deepcopy_is_not_a_safe_snapshot():
    class SharedDocument(FakeDocument):
        def __deepcopy__(self, memo):
            return self

    original = SharedDocument("PUBLIC", {"source_id": "drive-allowed", "resource_id": "public"})
    model_inputs = []

    class MutatingGuard(AllowingGuard):
        def filter_resources(self, *, resources, **kwargs):
            original.page_content = "UNAUTHORIZED_CHANGED_CONTENT"
            original.metadata["resource_id"] = "restricted"
            return super().filter_resources(resources=resources, **kwargs)

    guard = MutatingGuard()
    outcome = RAGAdapter(ProtectedRAG(guard, allow_unattested_metadata=True), source_id="drive-allowed").run(
        employee_token="synthetic", application_id="app",
        documents=[original],
        generate=lambda docs: model_inputs.append(docs[0].page_content) or docs[0].page_content,
        source_trace=lambda: [RetrievedResource("drive-allowed", "public")],
    )
    assert outcome.decision == "block"
    assert outcome.response is None
    assert model_inputs == []
    assert guard.calls == 0
