"""Internal Gateway authorization and provenance engine (not a customer SDK)."""

from .protection import GuardClient, ProtectedRAG, ProtectedResponse, RetrievedResource
from .attestation import (
    AttestationError, ContentBinding, SourceAttestationSigner, SourceAttestationVerifier,
)
from .ingestion import IngestionError, TrustedSourceIngestor, VerifiedSourceDocument
from .registry import AdapterRegistration, adapter_registry
from .authorized_retrieval import (
    AuthorizationScope,
    AuthorizedRetrievalResult,
    AuthorizedVectorRetriever,
    ScopeError,
)
from .pgvector_retrieval import PgVectorAuthorizedBackend

__all__ = [
    "AdapterRegistration",
    "AttestationError",
    "AuthorizationScope",
    "AuthorizedRetrievalResult",
    "AuthorizedVectorRetriever",
    "ContentBinding",
    "ScopeError",
    "GuardClient",
    "ProtectedRAG",
    "ProtectedResponse",
    "PgVectorAuthorizedBackend",
    "RetrievedResource",
    "SourceAttestationSigner",
    "SourceAttestationVerifier",
    "adapter_registry",
    "IngestionError",
    "TrustedSourceIngestor",
    "VerifiedSourceDocument",
    "CacheDependency",
    "CachedAnswerManifest",
    "CachedAnswerManifestSigner",
    "CachedAnswerManifestVerifier",
]

from .cache import CacheDependency, CachedAnswerManifest, CachedAnswerManifestSigner, CachedAnswerManifestVerifier
