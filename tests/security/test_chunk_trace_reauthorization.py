"""Chunk-scoped late provenance attacks at the synthetic Guard/SDK boundary.

These tests use only mock HTTP Guard responses and synthetic canary content.
"""
from __future__ import annotations

import httpx
import pytest

from packages.rag_sdk.protection import GuardClient, ProtectedRAG, RetrievedResource

CANARY = "SYNTHETIC_DENIED_CHUNK_CANARY_DO_NOT_RELEASE"
INITIAL = RetrievedResource("drive", "same-file", "safe-chunk", "allowed extract")


@pytest.mark.parametrize("late_resource,approved_chunks", [
    (RetrievedResource("drive", "same-file", "forbidden-chunk", derived_type="cache"), ["safe-chunk"]),
    (RetrievedResource("drive", "new-file", "forbidden-chunk", derived_type="tool"), ["different-chunk"]),
])
def test_late_chunk_not_authorized_even_if_document_id_matches(
    late_resource: RetrievedResource, approved_chunks: list[str],
) -> None:
    """Late provenance must use chunk scope, never only resource membership."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("filter-resources"):
            is_late = len([path for path in calls if path.endswith("filter-resources")]) > 1
            source = late_resource if is_late else INITIAL
            return httpx.Response(200, json={
                "decision_id": "decision-late" if is_late else "decision-initial",
                "decision": "allow", "mode": "protect",
                "allowed": [{
                    "source_id": source.source_id,
                    "resource_id": source.resource_id,
                    "chunk_ids": approved_chunks if is_late else ["safe-chunk"],
                }],
            })
        return httpx.Response(200, json={"decision": "allow", "reason": "OK"})

    client = GuardClient("https://local-synthetic.test", client=httpx.Client(
        transport=httpx.MockTransport(handler),
    ))
    rag = ProtectedRAG(client, allow_unattested_metadata=True)
    model_seen: list[str] = []
    result = rag.run(
        employee_token="synthetic", application_id="rag", request_id="chunk-late",
        retrieved=[INITIAL],
        generate=lambda allowed: (model_seen.extend(r.content for r in allowed) or CANARY),
        source_trace=lambda: [INITIAL, late_resource],
    )
    assert model_seen == ["allowed extract"]
    assert result.decision == "block"
    assert result.response is None
    assert calls.count("/guard/v1/filter-resources") == 2
    assert "/guard/v1/check-output" not in calls


@pytest.mark.parametrize("late_resource", [
    RetrievedResource("drive", "same-file", "new-approved-chunk", derived_type="cache"),
    RetrievedResource("drive", "new-file", "new-approved-chunk", derived_type="tool"),
])
def test_late_chunk_with_independent_approval_still_releases(late_resource: RetrievedResource) -> None:
    """Valid late sources are not accidentally disabled by the fix."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("filter-resources"):
            is_late = calls.count("/guard/v1/filter-resources") > 1
            source = late_resource if is_late else INITIAL
            return httpx.Response(200, json={
                "decision_id": "decision-late" if is_late else "decision-initial",
                "decision": "allow", "mode": "protect",
                "allowed": [{
                    "source_id": source.source_id, "resource_id": source.resource_id,
                    "chunk_ids": ["new-approved-chunk"] if is_late else ["safe-chunk"],
                }],
            })
        return httpx.Response(200, json={"decision": "allow", "reason": "OK"})

    client = GuardClient("https://local-synthetic.test", client=httpx.Client(
        transport=httpx.MockTransport(handler),
    ))
    result = ProtectedRAG(client, allow_unattested_metadata=True).run(
        employee_token="synthetic", application_id="rag", request_id="chunk-late-ok",
        retrieved=[INITIAL], generate=lambda _: "A permitted answer",
        source_trace=lambda: [INITIAL, late_resource],
    )
    assert result.decision == "allow"
    assert result.response == "A permitted answer"
    assert calls.count("/guard/v1/filter-resources") == 2
    assert calls[-1] == "/guard/v1/check-output"
