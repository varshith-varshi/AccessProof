"""Local AccessProof Guard primitives.

The guard is deliberately provider-neutral: adapters translate provider ACLs
into these immutable records, then every decision can be evaluated locally.
"""

from .policy import AccessDecision, AccessMode, AuthorizationPolicy, Guard
from .permissions import EffectiveAccessResolver, PermissionGrant, PermissionSnapshot

__all__ = [
    "AccessDecision", "AccessMode", "AuthorizationPolicy", "Guard",
    "EffectiveAccessResolver", "PermissionGrant", "PermissionSnapshot",
]
