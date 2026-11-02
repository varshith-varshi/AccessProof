"""Read-only, host-local discovery of candidate AccessProof RAG services.

Discovery is intentionally separate from installation.  Docker labels establish
only the supported integration contract; they never certify a route or give the
control plane permission to modify a customer service.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from typing import Iterable

from .installer import REQUIRED_LABELS, _labels

MAX_CONTAINERS = 500
MAX_TEXT = 255


class DiscoveryError(ValueError):
    """The local Docker inventory could not be read safely."""


@dataclass(frozen=True)
class DiscoveredApplication:
    stable_id: str
    display_name: str
    compose_project: str | None
    service: str | None
    image: str | None
    state: str
    reason: str
    existing_gateway: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "stable_id": self.stable_id, "display_name": self.display_name,
            "compose_project": self.compose_project, "service": self.service,
            "image": self.image, "state": self.state, "reason": self.reason,
            "existing_gateway": self.existing_gateway,
        }


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= MAX_TEXT else None


def _stable_id(project: str | None, service: str | None, image: str | None) -> str:
    # Docker container IDs change on a normal Compose recreation.  Bind the
    # durable discovery identity to the project/service/image tuple and require
    # re-verification when the image changes.
    material = "\0".join((project or "", service or "", image or ""))
    return "host-app-" + hashlib.sha256(material.encode()).hexdigest()[:24]


def _labels_from_row(row: dict[str, object]) -> dict[str, str]:
    raw = row.get("Labels") or row.get("labels") or {}
    if isinstance(raw, str):
        raw = [item for item in raw.split(",") if "=" in item]
    try:
        return _labels(raw)
    except ValueError:
        return {}


def discover(rows: Iterable[dict[str, object]]) -> list[DiscoveredApplication]:
    """Classify bounded Docker inventory records without executing containers.

    Expected fields are the sanitized output of ``docker ps --format json`` and
    optional inspected labels.  Unknown/malformed rows are excluded rather than
    guessed to be chatbots.
    """
    result: list[DiscoveredApplication] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        if index >= MAX_CONTAINERS or not isinstance(row, dict):
            break
        labels = _labels_from_row(row)
        project = _text(labels.get("com.docker.compose.project"))
        service = _text(labels.get("com.docker.compose.service"))
        image = _text(row.get("Image") or row.get("image"))
        name = _text(row.get("Names") or row.get("name"))
        if not name:
            continue
        is_gateway = (service == "accessproof-gateway" or "accessproof-gateway" in name
                      or labels.get("com.accessproof.gateway.instance") == "true")
        if is_gateway:
            continue
        key = _stable_id(project, service, image)
        if key in seen:
            continue
        seen.add(key)
        contract_ok = all(labels.get(key) == value for key, value in REQUIRED_LABELS.items())
        route_env = labels.get("com.accessproof.gateway.route_env")
        looks_service = bool(project and service)
        if contract_ok and route_env:
            state, reason = "SUPPORTED", "Declared AccessProof Gateway integration contract."
        elif looks_service and any(token in (service or name).lower() for token in ("rag", "chat", "assistant", "llm")):
            state, reason = "REQUIRES_INTEGRATION", "RAG-like service lacks the verified AccessProof adapter contract."
        elif looks_service:
            state, reason = "NON_AI_SERVICE", "No supported AI integration contract was observed."
        else:
            state, reason = "AMBIGUOUS", "Docker Compose project/service identity is unavailable."
        result.append(DiscoveredApplication(
            stable_id=key, display_name=service or name, compose_project=project,
            service=service, image=image, state=state, reason=reason,
        ))
    return sorted(result, key=lambda item: (item.compose_project or "", item.display_name, item.stable_id))


def docker_inventory() -> list[dict[str, object]]:
    """Return a bounded, non-secret Docker container inventory.

    The caller receives only Docker's list metadata.  Discovery deliberately
    does not inspect environments, execute containers, read mounted files, or
    contact a control plane.  Compose labels are part of ``docker ps`` output
    and are enough to classify a declared integration without treating it as
    security evidence.
    """
    try:
        completed = subprocess.run(
            ["docker", "ps", "--format", "{{json .}}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DiscoveryError("DOCKER_DISCOVERY_UNAVAILABLE") from exc
    rows: list[dict[str, object]] = []
    for line in completed.stdout.splitlines()[:MAX_CONTAINERS]:
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except ValueError as exc:
            raise DiscoveryError("DOCKER_DISCOVERY_INVALID") from exc
        if not isinstance(value, dict):
            raise DiscoveryError("DOCKER_DISCOVERY_INVALID")
        # Keep only fields intentionally used by the classifier.  In
        # particular, don't accidentally retain an environment-like field if
        # Docker changes its formatted output in a future version.
        rows.append({key: value.get(key) for key in ("ID", "Names", "Image", "State", "Status", "Labels")})
    return rows
