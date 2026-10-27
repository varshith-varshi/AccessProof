from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable


@dataclass(frozen=True)
class PermissionGrant:
    subject_id: str
    resource_id: str
    effect: str = "allow"
    source_id: str = ""
    scope: str = "read"
    group_id: str | None = None
    version: int = 0


@dataclass
class PermissionSnapshot:
    grants: list[PermissionGrant] = field(default_factory=list)
    version: int = 0
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class EffectiveAccessResolver:
    """Resolve a subject/resource pair from all current grants.

    Membership is additive: removing one group does not revoke access while
    another active grant still allows it. Explicit denies take precedence.
    """

    def __init__(self, snapshot: PermissionSnapshot):
        self.snapshot = snapshot

    def allowed(self, subject_id: str, resource_id: str, scope: str = "read") -> bool:
        matches = [g for g in self.snapshot.grants if g.subject_id == subject_id and g.resource_id == resource_id and g.scope == scope]
        if any(g.effect.lower() == "deny" for g in matches):
            return False
        return any(g.effect.lower() == "allow" for g in matches)

    def batch(self, subject_id: str, resource_ids: Iterable[str], scope: str = "read") -> dict[str, bool]:
        return {resource_id: self.allowed(subject_id, resource_id, scope) for resource_id in resource_ids}
