"""Fail-closed planning for exactly one selected Docker RAG.

AccessProof can discover several chatbots on the same host, but onboarding
connects exactly ONE. The plan matches the existing single-Gateway installer:
one legacy service name and the existing single loopback port.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .application_discovery import DiscoveredApplication

DEFAULT_GATEWAY_PORT = 8090
DEFAULT_GATEWAY_SERVICE = "accessproof-gateway"


class SelectionPlanError(ValueError):
    pass


@dataclass(frozen=True)
class PlannedApplication:
    stable_id: str
    compose_project: str
    rag_service: str
    gateway_service: str
    listen_port: int


def plan_selection(
    discovered: Iterable[DiscoveredApplication], selected_ids: Iterable[str], *,
    occupied_ports: Iterable[int] = (),
) -> list[PlannedApplication]:
    """One chatbot, one existing Gateway contract, with no Docker mutations.

    A plan does not reserve a host port, verify identity or certify protection.
    The installer must independently recheck deployment state before approval.
    """
    listed = list(discovered)
    inventory = {entry.stable_id: entry for entry in listed}
    if len(listed) != len(inventory):
        raise SelectionPlanError("Ambiguous duplicate discovered application identity")
    wanted = list(selected_ids)
    if len(wanted) != 1:
        raise SelectionPlanError("Select exactly one discovered chatbot")
    app = inventory.get(wanted[0])
    if app is None:
        raise SelectionPlanError("Selected chatbot is no longer present in this host inventory")
    if app.state != "SUPPORTED":
        raise SelectionPlanError("Only a chatbot with the declared adapter contract can be planned")
    if not app.compose_project or not app.service:
        raise SelectionPlanError("Selected chatbot lacks a Compose project or service identity")
    for port in occupied_ports:
        if type(port) is not int or not 1 <= port <= 65535:
            raise SelectionPlanError("Host port inventory is invalid")
        if port == DEFAULT_GATEWAY_PORT:
            raise SelectionPlanError("Default Gateway port 8090 is already published; review the existing installation")
    return [PlannedApplication(
        stable_id=app.stable_id,
        compose_project=app.compose_project,
        rag_service=app.service,
        gateway_service=DEFAULT_GATEWAY_SERVICE,
        listen_port=DEFAULT_GATEWAY_PORT,
    )]
