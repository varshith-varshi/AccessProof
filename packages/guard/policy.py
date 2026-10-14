from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Iterable

from .permissions import EffectiveAccessResolver


class AccessMode(StrEnum):
    SHADOW = "shadow"
    PROTECT = "protect"


class AccessDecision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    WOULD_ALLOW = "would_allow"
    WOULD_BLOCK = "would_block"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass(frozen=True)
class AuthorizationPolicy:
    policy_id: str
    version: int
    mode: AccessMode = AccessMode.SHADOW
    fail_closed: bool = True
    break_glass: bool = False
    application_ids: frozenset[str] = frozenset()


@dataclass
class Guard:
    resolver: EffectiveAccessResolver
    policy: AuthorizationPolicy
    audit: list[dict] = field(default_factory=list)

    def authorize(self, *, subject_id: str | None, application_id: str, resource_ids: Iterable[str]) -> tuple[AccessDecision, list[str]]:
        resources = list(dict.fromkeys(resource_ids))
        if self.policy.application_ids and application_id not in self.policy.application_ids:
            return self._record(AccessDecision.UNKNOWN, subject_id, application_id, resources, "application_not_bound")
        if self.policy.break_glass:
            return self._record(AccessDecision.ALLOW, subject_id, application_id, resources, "break_glass")
        if not subject_id:
            decision = AccessDecision.WOULD_BLOCK if self.policy.mode == AccessMode.SHADOW else AccessDecision.BLOCK
            return self._record(decision, subject_id, application_id, resources, "missing_trusted_subject")
        allowed = self.resolver.batch(subject_id, resources)
        denied = [rid for rid, ok in allowed.items() if not ok]
        if denied:
            decision = AccessDecision.WOULD_BLOCK if self.policy.mode == AccessMode.SHADOW else AccessDecision.BLOCK
            return self._record(decision, subject_id, application_id, denied, "effective_access_denied")
        decision = AccessDecision.WOULD_ALLOW if self.policy.mode == AccessMode.SHADOW else AccessDecision.ALLOW
        return self._record(decision, subject_id, application_id, resources, "effective_access_allowed")

    def _record(self, decision, subject_id, application_id, resources, reason):
        self.audit.append({"decision": decision.value, "subject_id": subject_id, "application_id": application_id, "resource_ids": resources, "reason": reason, "policy_id": self.policy.policy_id, "policy_version": self.policy.version})
        return decision, resources
