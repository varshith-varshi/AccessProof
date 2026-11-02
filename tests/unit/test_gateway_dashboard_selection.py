"""Dashboard-mediated one-chatbot selection bound to existing ephemeral pairing."""
from __future__ import annotations


import fakeredis
import httpx
import pytest
from fastapi.testclient import TestClient

from apps.api.accessproof_api import gateway_pairing
from apps.api.accessproof_api.app import app
from apps.gateway.accessproof_gateway import customer_connect
from apps.gateway.accessproof_gateway.application_discovery import DiscoveredApplication


@pytest.fixture()
def redis_pairing(monkeypatch):
    instance = fakeredis.FakeRedis()
    monkeypatch.setattr(gateway_pairing, "_client", lambda: instance)
    yield instance
    instance.flushall()


def _app(suffix: str, state: str = "SUPPORTED") -> dict[str, str]:
    return {
        "stable_id": "host-app-" + suffix * 24,
        "display_name": "Finance RAG" if suffix == "a" else "HR RAG",
        "compose_project": "test-enterprise",
        "service": "finance-rag" if suffix == "a" else "hr-rag",
        "state": state,
    }


def _issue() -> dict:
    return gateway_pairing.issue(org_id="org-one", app_row_id="app-row-one",
                                 application_id="customer-rag-one", api_url="https://api.accessproof.in")


def test_paired_host_inventory_is_sanitized_and_one_admin_choice_consumed(redis_pairing):
    pairing = _issue()
    token = pairing["pairing_token"]
    apps = [_app("a"), _app("b", "REQUIRES_INTEGRATION")]
    status = gateway_pairing.publish_discovery(token=token, applications=apps)
    assert status["state"] == "awaiting_dashboard_selection"
    visible = gateway_pairing.discovery_status(org_id="org-one", app_row_id="app-row-one")
    assert visible["state"] == "awaiting_selection"
    assert len(visible["applications"]) == 2
    assert "pairing_token" not in str(visible)
    with pytest.raises(gateway_pairing.PairingError, match="SELECTED_CHATBOT_NOT_SUPPORTED"):
        gateway_pairing.select_discovered(org_id="org-one", app_row_id="app-row-one",
                                          stable_id=_app("b")["stable_id"])
    selected = gateway_pairing.select_discovered(org_id="org-one", app_row_id="app-row-one",
                                                stable_id=_app("a")["stable_id"])
    assert selected["state"] == "selected"
    assert gateway_pairing.selected_for_host(token=token)["selected_id"] == _app("a")["stable_id"]
    with pytest.raises(gateway_pairing.PairingError, match="ALREADY_SELECTED"):
        gateway_pairing.select_discovered(org_id="org-one", app_row_id="app-row-one",
                                          stable_id=_app("b")["stable_id"])
    with pytest.raises(gateway_pairing.PairingError, match="ALREADY_SELECTED"):
        gateway_pairing.publish_discovery(token=token, applications=apps)


def test_new_pairing_invalidates_stale_inventory_and_old_token(redis_pairing):
    first = _issue()
    gateway_pairing.publish_discovery(token=first["pairing_token"], applications=[_app("a")])
    second = _issue()
    assert gateway_pairing.discovery_status(org_id="org-one", app_row_id="app-row-one")["state"] == "not_ready"
    with pytest.raises(gateway_pairing.PairingError, match="SUPERSEDED"):
        gateway_pairing.selected_for_host(token=first["pairing_token"])
    gateway_pairing.publish_discovery(token=second["pairing_token"], applications=[_app("b")])
    assert gateway_pairing.select_discovered(
        org_id="org-one", app_row_id="app-row-one", stable_id=_app("b")["stable_id"],
    )["state"] == "selected"


def test_inventory_rejects_extra_fields_and_invalid_ids(redis_pairing):
    token = _issue()["pairing_token"]
    with pytest.raises(gateway_pairing.PairingError, match="INVALID_FIELDS"):
        gateway_pairing.publish_discovery(
            token=token, applications=[dict(_app("a"), employee_token="secret")],
        )
    with pytest.raises(gateway_pairing.PairingError, match="INVALID_ID"):
        gateway_pairing.publish_discovery(
            token=token, applications=[dict(_app("a"), stable_id="../../a")],
        )
    with pytest.raises(gateway_pairing.PairingError, match="TOO_LARGE"):
        gateway_pairing.publish_discovery(token=token, applications=[_app("a")] * 33)
    assert gateway_pairing.discovery_status(org_id="org-one", app_row_id="app-row-one")["state"] == "not_ready"


def test_expired_or_consumed_pairing_denies_machine_selection(redis_pairing):
    token = _issue()["pairing_token"]
    gateway_pairing.publish_discovery(token=token, applications=[_app("a")])
    redis_pairing.delete(gateway_pairing._token_key(token))
    with pytest.raises(gateway_pairing.PairingError, match="EXPIRED"):
        gateway_pairing.selected_for_host(token=token)


def test_machine_discovery_endpoints_require_pairing_bearer():
    client = TestClient(app)
    assert client.post("/api/v1/gateway-pairings/discovery", json={"applications": []}).status_code == 401
    assert client.get("/api/v1/gateway-pairings/discovery/selection").status_code == 401


def test_host_client_waits_only_for_whitelisted_supported_id(monkeypatch):
    apps = [
        DiscoveredApplication(_app("a")["stable_id"], "Finance RAG", "finance", "finance-rag", "rag:1", "SUPPORTED", "test"),
        DiscoveredApplication(_app("b")["stable_id"], "HR RAG", "hr", "hr-rag", "rag:1", "REQUIRES_INTEGRATION", "test"),
    ]
    calls = []
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "POST":
            assert request.headers["Authorization"] == "Bearer " + ("p" * 50)
            data = __import__("json").loads(request.content)
            assert len(data["applications"]) == 2
            assert set(data["applications"][0]) == {"stable_id", "display_name", "compose_project", "service", "state"}
            return httpx.Response(200, json={"state": "awaiting_dashboard_selection"})
        return httpx.Response(200, json={"state": "selected", "selected_id": apps[0].stable_id})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        choice = customer_connect.await_dashboard_chatbot(
            {"control_plane_url": "https://api.accessproof.in", "pairing_token": "p" * 50},
            apps, client=client,
        )
    assert choice == apps[0].stable_id
    assert len(calls) == 2


def test_host_refuses_unsupported_dashboard_selection():
    apps = [DiscoveredApplication(_app("a")["stable_id"], "Finance RAG", "finance", "finance-rag", "rag:1", "SUPPORTED", "test")]
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"state": "awaiting_dashboard_selection"})
        return httpx.Response(200, json={"state": "selected", "selected_id": _app("b")["stable_id"]})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(customer_connect.ConnectError, match="invalid/unsupported"):
            customer_connect.await_dashboard_chatbot(
                {"control_plane_url": "https://api.accessproof.in", "pairing_token": "p" * 50},
                apps, client=client,
            )
