"""Read-only, host-local discovery of candidate AccessProof RAG services.

Discovery is intentionally separate from installation.  Docker labels establish
only the supported integration contract; they never certify a route or give the
control plane permission to modify a customer service.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .installer import REQUIRED_LABELS, _ALLOWED_ENV, _ALLOWED_NAME, _labels

MAX_CONTAINERS = 500
MAX_TEXT = 255
_PUBLISHED_PORT = re.compile(r":([0-9]{1,5})->[0-9]+/(?:tcp|udp)")


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
        if index >= MAX_CONTAINERS:
            raise DiscoveryError("DOCKER_DISCOVERY_TRUNCATED")
        if not isinstance(row, dict):
            continue
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
        looks_service = bool(project and service and _ALLOWED_NAME.fullmatch(service))
        route_valid = isinstance(route_env, str) and _ALLOWED_ENV.fullmatch(route_env) is not None
        # Labels are a declaration of compatibility, never independent
        # authorization evidence or proof that Guard protection is active.
        candidate_name = (service or name).lower()
        rag_like = re.search(r"(?:^|[-_.])(rag|chat|chatbot|assistant|llm)(?:$|[-_.])", candidate_name) is not None
        if looks_service and contract_ok and route_valid:
            state, reason = "SUPPORTED", "Declared AccessProof Gateway integration contract."
        elif looks_service and (rag_like or contract_ok or bool(route_env)):
            state, reason = "REQUIRES_INTEGRATION", "RAG candidate needs a valid verified AccessProof adapter contract."
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
    lines = completed.stdout.splitlines()
    if len(lines) > MAX_CONTAINERS:
        raise DiscoveryError("DOCKER_DISCOVERY_TRUNCATED")
    for line in lines:
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
        rows.append({key: value.get(key) for key in (
            "ID", "Names", "Image", "State", "Status", "Labels", "Ports",
        )})
    return rows


def published_host_ports(rows: Iterable[dict[str, object]]) -> set[int]:
    """Extract only published numeric ports from Docker's summary field.

    This is used for local collision avoidance, never as a network scan or as
    evidence that an endpoint is safe.  Unparseable values are ignored rather
    than transformed into a guessed port reservation.
    """
    result: set[int] = set()
    for index, row in enumerate(rows):
        if index >= MAX_CONTAINERS:
            break
        ports = row.get("Ports") or row.get("ports")
        if not isinstance(ports, str) or len(ports) > MAX_TEXT * 4:
            continue
        for raw in _PUBLISHED_PORT.findall(ports):
            port = int(raw)
            if 1 <= port <= 65535:
                result.add(port)
    return result


def compose_for_selected(
    selected: DiscoveredApplication,
    rows: Iterable[dict[str, object]],
    *,
    explicit_compose: Path | None = None,
) -> Path:
    """Resolve the one chosen running Compose service to its original project.

    This is customer-host-local read-only Docker inspection. The selected
    Docker container and Compose labels must still match the discovered
    identity; never guess a project directory from the service display name.
    """
    if (selected.state != "SUPPORTED" or not selected.compose_project
            or not selected.service):
        raise DiscoveryError("SELECTED_RAG_NOT_SUPPORTED")
    matches = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        labels = _labels_from_row(row)
        if (labels.get("com.docker.compose.project") == selected.compose_project
                and labels.get("com.docker.compose.service") == selected.service
                and _stable_id(selected.compose_project, selected.service,
                               _text(row.get("Image") or row.get("image"))) == selected.stable_id):
            matches.append(row)
    if len(matches) != 1:
        raise DiscoveryError("SELECTED_RAG_RUNTIME_AMBIGUOUS")
    identifier = matches[0].get("ID")
    if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{12,64}", identifier):
        raise DiscoveryError("SELECTED_RAG_CONTAINER_ID_MISSING")
    try:
        inspected = subprocess.run(
            ["docker", "inspect", "--type=container", identifier],
            check=True, capture_output=True, text=True, timeout=15,
        )
        objects = json.loads(inspected.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise DiscoveryError("SELECTED_RAG_INSPECTION_FAILED") from exc
    if not isinstance(objects, list) or len(objects) != 1 or not isinstance(objects[0], dict):
        raise DiscoveryError("SELECTED_RAG_INSPECTION_INVALID")
    container = objects[0]
    labels = (container.get("Config") or {}).get("Labels") or {}
    if (not isinstance(labels, dict) or
            not isinstance(container.get("Id"), str) or
            not container["Id"].startswith(identifier) or
            labels.get("com.docker.compose.project") != selected.compose_project or
            labels.get("com.docker.compose.service") != selected.service or
            (container.get("State") or {}).get("Status") != "running" or
            any(labels.get(key) != value for key, value in REQUIRED_LABELS.items()) or
            not isinstance(labels.get("com.accessproof.gateway.route_env"), str) or
            _ALLOWED_ENV.fullmatch(labels["com.accessproof.gateway.route_env"]) is None):
        raise DiscoveryError("SELECTED_RAG_CHANGED_SINCE_DISCOVERY")

    paths = labels.get("com.docker.compose.project.config_files", "")
    options = [Path(item) for item in paths.split(",") if item] if isinstance(paths, str) else []
    if not options or any(not candidate.is_absolute() for candidate in options):
        raise DiscoveryError("SELECTED_RAG_COMPOSE_PATH_MISSING")
    if explicit_compose is None:
        if len(options) != 1:
            raise DiscoveryError("SELECTED_RAG_MULTIPLE_COMPOSE_FILES_REQUIRE_REVIEW")
        chosen = options[0]
    else:
        chosen = explicit_compose.expanduser()
        if chosen.is_symlink() or not chosen.is_file() or chosen.resolve() not in {
            option.resolve() for option in options if not option.is_symlink()
        }:
            raise DiscoveryError("SELECTED_RAG_COMPOSE_MISMATCH")
    if chosen.is_symlink() or not chosen.is_file():
        raise DiscoveryError("SELECTED_RAG_COMPOSE_FILE_UNSAFE")
    return chosen.resolve()
