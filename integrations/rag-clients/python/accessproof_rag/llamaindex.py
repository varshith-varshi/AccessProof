"""LlamaIndex integration: a query engine whose generation happens behind the Gateway.

    from accessproof_rag.llamaindex import AccessProofQueryEngine
    engine = AccessProofQueryEngine(retriever=index.as_retriever(), gateway=gateway, employee_token=token)
    response = engine.query(question)

Retrieved nodes must carry AccessProof trusted-ingestion metadata and the exact
attested text. No local LLM is configured or called.
"""
from __future__ import annotations

from typing import Any

from llama_index.core.base.base_retriever import BaseRetriever
from llama_index.core.base.response.schema import Response
from llama_index.core.query_engine import CustomQueryEngine

from .client import AccessProofGateway, TrustedChunk


class AccessProofQueryEngine(CustomQueryEngine):
    retriever: BaseRetriever
    gateway: Any
    employee_token: str
    request_id: str | None = None

    def custom_query(self, query_str: str) -> Response:
        nodes = self.retriever.retrieve(query_str)
        chunks = [TrustedChunk.from_metadata(n.node.get_content(), n.node.metadata) for n in nodes]
        gateway: AccessProofGateway = self.gateway
        answer = gateway.answer(self.employee_token, query_str, chunks, request_id=self.request_id)
        return Response(response=answer.text, source_nodes=[],
                        metadata={"decision_id": answer.decision_id, "request_id": answer.request_id})
