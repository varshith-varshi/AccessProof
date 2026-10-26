"""Framework-neutral safe RAG integration for an AccessProof Guard."""

from .protection import GuardClient, ProtectedRAG, ProtectedResponse, RetrievedResource
from .attestation import (
    AttestationError, ContentBinding, SourceAttestationSigner, SourceAttestationVerifier,
)
from .ingestion import IngestionError, TrustedSourceIngestor, VerifiedSourceDocument
from .adapters import (
    ADAPTER_CONTRACT_VERSION,
    AdapterCapabilities,
    AdapterConfigurationError,
    HaystackAdapter,
    LangChainAdapter,
    LlamaIndexAdapter,
    RAGAdapter,
    adapter_capability_matrix,
    normalize_document,
    normalize_documents,
)
from .registry import AdapterRegistration, adapter_registry
from .authorized_retrieval import (
    AuthorizationScope,
    AuthorizedRetrievalResult,
    AuthorizedVectorRetriever,
    ScopeError,
)
from .pgvector_retrieval import PgVectorAuthorizedBackend

__all__ = [
    "ADAPTER_CONTRACT_VERSION",
    "AdapterCapabilities",
    "AdapterConfigurationError",
    "AdapterRegistration",
    "AttestationError",
    "AuthorizationScope",
    "AuthorizedRetrievalResult",
    "AuthorizedVectorRetriever",
    "ContentBinding",
    "ScopeError",
    "GuardClient",
    "HaystackAdapter",
    "LangChainAdapter",
    "LlamaIndexAdapter",
    "ProtectedRAG",
    "ProtectedResponse",
    "PgVectorAuthorizedBackend",
    "RAGAdapter",
    "RetrievedResource",
    "SourceAttestationSigner",
    "SourceAttestationVerifier",
    "adapter_capability_matrix",
    "adapter_registry",
    "IngestionError",
    "TrustedSourceIngestor",
    "VerifiedSourceDocument",
    "normalize_document",
    "normalize_documents",
    "CacheDependency",
    "CachedAnswerManifest",
    "CachedAnswerManifestSigner",
    "CachedAnswerManifestVerifier",
]

from .cache import CacheDependency, CachedAnswerManifest, CachedAnswerManifestSigner, CachedAnswerManifestVerifier
