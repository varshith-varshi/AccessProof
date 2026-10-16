"""Framework-neutral safe RAG integration for an AccessProof Guard."""

from .protection import GuardClient, ProtectedRAG, ProtectedResponse, RetrievedResource

__all__ = ["GuardClient", "ProtectedRAG", "ProtectedResponse", "RetrievedResource"]
