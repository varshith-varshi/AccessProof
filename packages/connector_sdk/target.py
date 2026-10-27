from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from packages.domain.models import EvidenceLevel, Principal


@dataclass(slots=True)
class TargetObservation:
    available: bool
    answer: str = ""
    citations: list[str] = field(default_factory=list)
    retrieved_documents: list[str] = field(default_factory=list)
    tool_outputs: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    status_code: int | None = None


@dataclass(slots=True)
class OracleMatch:
    exposed: bool
    level: EvidenceLevel | None = None
    signal: str | None = None


class AITargetAdapter(ABC):
    @abstractmethod
    async def validate_connection(self) -> None: ...

    @abstractmethod
    async def probe(self, *, principal: Principal, prompt: str) -> TargetObservation: ...
