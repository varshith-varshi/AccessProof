"""A buffered, fail-closed reference integration for customer RAG applications.

The API intentionally makes release dependent on both Guard layers.  It accepts
retrieved objects only when they carry stable source/resource metadata and never
streams model bytes before post-generation verification succeeds.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import httpx


@dataclass(frozen=True)
class RetrievedResource:
    source_id: str
    resource_id: str
    chunk_id: str | None = None
    content: str = ""
    derived_id: str | None = None
    derived_type: str = "retrieval"


@dataclass(frozen=True)
class ProtectedResponse:
    decision: str
    response: str | None
    reason: str
    decision_id: str | None = None
    regenerated: bool = False


class GuardClient:
    def __init__(self, base_url: str, *, timeout_seconds: float = 10.0, client: httpx.Client | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = client or httpx.Client(timeout=timeout_seconds, follow_redirects=False, trust_env=False)
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def filter_resources(self, *, employee_token: str, application_id: str, request_id: str, resources: list[RetrievedResource]) -> dict[str, Any]:
        payload = {"application_id": application_id, "request_id": request_id, "resources": [
            {"source_id": item.source_id, "resource_id": item.resource_id, "scope": "read", "chunk_ids": [item.chunk_id] if item.chunk_id else []}
            for item in resources
        ]}
        response = self.client.post(f"{self.base_url}/guard/v1/filter-resources", headers={"Authorization": f"Bearer {employee_token}"}, json=payload)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("decision_id"), str):
            raise ValueError("Guard returned an invalid Layer 1 decision")
        return data

    def check_output(self, *, employee_token: str, application_id: str, request_id: str, decision_id: str, resources: list[RetrievedResource]) -> dict[str, Any]:
        resource_ids = sorted({item.resource_id for item in resources})
        provenance = [{
            "derived_id": item.derived_id or item.chunk_id or item.resource_id,
            "derived_type": item.derived_type,
            "source_resource_ids": [item.resource_id],
        } for item in resources]
        response = self.client.post(f"{self.base_url}/guard/v1/check-output", headers={"Authorization": f"Bearer {employee_token}"}, json={
            "decision_id": decision_id, "application_id": application_id, "request_id": request_id,
            "used_resource_ids": resource_ids, "provenance": provenance,
        })
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("decision"), str):
            raise ValueError("Guard returned an invalid Layer 2 decision")
        return data


class ProtectedRAG:
    """Runs retrieve → Layer 1 → model buffer → Layer 2 → release.

    ``generate`` receives only authorized resources.  A generator response is
    fully bounded and collected before Layer 2, so Protect mode never leaks a
    first streamed token before authorization completes.
    """
    def __init__(self, guard: GuardClient, *, max_response_bytes: int = 1_000_000, max_regenerations: int = 1) -> None:
        self.guard = guard
        self.max_response_bytes = max_response_bytes
        self.max_regenerations = max(0, max_regenerations)

    @staticmethod
    def _authorized(resources: list[RetrievedResource], layer1: dict[str, Any]) -> list[RetrievedResource]:
        allowed = {(str(item["source_id"]), str(item["resource_id"])) for item in layer1.get("allowed", [])}
        return [item for item in resources if (item.source_id, item.resource_id) in allowed]

    def _buffer(self, generated: str | Iterable[str]) -> str:
        parts = [generated] if isinstance(generated, str) else generated
        body = ""
        for part in parts:
            if not isinstance(part, str):
                raise TypeError("The model callback must produce text")
            body += part
            if len(body.encode("utf-8")) > self.max_response_bytes:
                raise ValueError("Model response exceeds AccessProof response buffer limit")
        return body

    def run(self, *, employee_token: str, application_id: str, retrieved: list[RetrievedResource], generate: Callable[[list[RetrievedResource]], str | Iterable[str]], request_id: str | None = None, regenerate: Callable[[list[RetrievedResource]], str | Iterable[str]] | None = None) -> ProtectedResponse:
        if not retrieved:
            return ProtectedResponse("block", None, "NO_RETRIEVED_RESOURCES")
        if any(not item.source_id or not item.resource_id for item in retrieved):
            return ProtectedResponse("block", None, "RESOURCE_METADATA_REQUIRED")
        request_id = request_id or str(uuid4())
        layer1 = self.guard.filter_resources(employee_token=employee_token, application_id=application_id, request_id=request_id, resources=retrieved)
        if layer1["decision"] not in {"allow", "would_allow"}:
            return ProtectedResponse(str(layer1["decision"]), None, "LAYER1_BLOCK", str(layer1["decision_id"]))
        authorized = self._authorized(retrieved, layer1)
        answer = self._buffer(generate(authorized))
        layer2 = self.guard.check_output(employee_token=employee_token, application_id=application_id, request_id=request_id, decision_id=str(layer1["decision_id"]), resources=authorized)
        if layer2["decision"] in {"allow", "would_allow"}:
            return ProtectedResponse(str(layer2["decision"]), answer, str(layer2["reason"]), str(layer1["decision_id"]))
        if regenerate and self.max_regenerations:
            # A fresh Layer 1 context is intentional: Layer 2 contexts are one-time use.
            retry = self.guard.filter_resources(employee_token=employee_token, application_id=application_id, request_id=request_id, resources=authorized)
            if retry["decision"] in {"allow", "would_allow"}:
                retried_answer = self._buffer(regenerate(authorized))
                verified = self.guard.check_output(employee_token=employee_token, application_id=application_id, request_id=request_id, decision_id=str(retry["decision_id"]), resources=authorized)
                if verified["decision"] in {"allow", "would_allow"}:
                    return ProtectedResponse(str(verified["decision"]), retried_answer, str(verified["reason"]), str(retry["decision_id"]), True)
        return ProtectedResponse(str(layer2["decision"]), None, str(layer2["reason"]), str(layer1["decision_id"]))
