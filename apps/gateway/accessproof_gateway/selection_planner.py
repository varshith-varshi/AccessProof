"""Explicit, fail-closed planning for selected Docker RAG applications.

This module makes no Docker changes.  It exists so a host agent and the
dashboard can derive the same per-application Gateway names and loopback ports
from an authenticated, persisted selection rather than selecting every service
or guessing from a container name.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable

from .application_discovery import DiscoveredApplication

_SERVICE_SAFE = re.compile(r"[^a-z0-9-]+")
DEFAULT_PORT_START = 18090
DEFAULT_PORT_END = 18189


class SelectionPlanError(ValueError):
    pass


@dataclass(frozen=True)
class PlannedApplication:
    stable_id: str
    compose_project: str
    rag_service: str
    gateway_service: str
    listen_port: int


def _gateway_service(app: DiscoveredApplication) -> str:
    # A readable prefix helps customer operators; a hash avoids collisions for
    # equal service names across Compose projects and survives recreation.
    readable = _SERVICE_SAFE.sub("-", app.display_name.lower()).strip("-")[:48] or "rag"
    suffix = hashlib.sha256(app.stable_id.encode()).hexdigest()[:10]
    return f"accessproof-gateway-{readable}-{suffix}"


def plan_selection(
    discovered: Iterable[DiscoveredApplication], selected_ids: Iterable[str], *,
    occupied_ports: Iterable[int] = (), port_start: int = DEFAULT_PORT_START,
    port_end: int = DEFAULT_PORT_END,
) -> list[PlannedApplication]:
    """Create independent plans only for explicitly selected supported apps.

    Ports are loopback-only values for the generated Compose override.  Caller
    supplies host-observed ports so planning cannot silently collide with an
    existing customer endpoint.  A changed stable identity needs a new plan
    and re-verification rather than inheriting an old application's boundary.
    """
    if type(port_start) is not int or type(port_end) is not int or not 1024 <= port_start <= port_end <= 65535:
        raise SelectionPlanError("Invalid Gateway port allocation range")
    inventory = {entry.stable_id: entry for entry in discovered}
    wanted = list(selected_ids)
    if not wanted or len(wanted) != len(set(wanted)):
        raise SelectionPlanError("Select one or more distinct discovered applications")
    selected: list[DiscoveredApplication] = []
    for stable_id in wanted:
        app = inventory.get(stable_id)
        if app is None:
            raise SelectionPlanError("Selected application is no longer present in this host inventory")
        if app.state != "SUPPORTED":
            raise SelectionPlanError("Only applications with the verified adapter contract can be planned")
        if not app.compose_project or not app.service:
            raise SelectionPlanError("Selected application lacks a durable Compose project/service identity")
        selected.append(app)
    used = set()
    for occupied_port in occupied_ports:
        if type(occupied_port) is not int or not 1 <= occupied_port <= 65535:
            raise SelectionPlanError("Host port inventory is invalid")
        used.add(occupied_port)
    result: list[PlannedApplication] = []
    for app in sorted(selected, key=lambda item: item.stable_id):
        port: int | None = None
        for candidate in range(port_start, port_end + 1):
            if candidate not in used:
                port = candidate
                break
        if port is None:
            raise SelectionPlanError("No approved loopback Gateway port is available; do not reuse an occupied port")
        used.add(port)
        project = app.compose_project
        service = app.service
        if project is None or service is None:  # guarded above; preserve type and fail closed.
            raise SelectionPlanError("Selected application lacks a durable Compose project/service identity")
        result.append(PlannedApplication(
            stable_id=app.stable_id,
            compose_project=project,
            rag_service=service,
            gateway_service=_gateway_service(app),
            listen_port=port,
        ))
    return result
