"""AccessProof RAG integration: connect an existing RAG (any OS/framework) to a Gateway."""
from .client import (
    AccessDenied, AccessProofError, AccessProofGateway, IdentityRejected, ProtectedAnswer,
    ProtectionUnavailable, TrustedChunk, UntrustedChunk,
)

__all__ = ["AccessDenied", "AccessProofError", "AccessProofGateway", "IdentityRejected", "ProtectedAnswer",
           "ProtectionUnavailable", "TrustedChunk", "UntrustedChunk"]
__version__ = "0.1.0"
