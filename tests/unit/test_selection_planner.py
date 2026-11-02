from __future__ import annotations

import pytest

from apps.gateway.accessproof_gateway.application_discovery import DiscoveredApplication
from apps.gateway.accessproof_gateway.selection_planner import SelectionPlanError, plan_selection


def _app(stable_id: str, project: str, service: str, state: str = "SUPPORTED") -> DiscoveredApplication:
    return DiscoveredApplication(stable_id, service, project, service, "rag:1", state, "test")


def test_only_explicitly_selected_supported_apps_receive_independent_plans():
    finance = _app("host-finance", "finance", "rag")
    hr = _app("host-hr", "hr", "rag")
    ignored = _app("host-sales", "sales", "rag", "REQUIRES_INTEGRATION")
    plans = plan_selection([finance, hr, ignored], [finance.stable_id, hr.stable_id], occupied_ports=[18090])
    assert [(item.compose_project, item.rag_service, item.listen_port) for item in plans] == [
        ("finance", "rag", 18091), ("hr", "rag", 18092),
    ]
    assert len({item.gateway_service for item in plans}) == 2
    assert all(item.gateway_service.startswith("accessproof-gateway-rag-") for item in plans)


def test_planner_rejects_unselected_stale_or_unsupported_apps():
    supported = _app("supported", "finance", "finance-rag")
    unsupported = _app("unsupported", "sales", "sales-rag", "REQUIRES_INTEGRATION")
    with pytest.raises(SelectionPlanError, match="verified adapter"):
        plan_selection([supported, unsupported], [unsupported.stable_id])
    with pytest.raises(SelectionPlanError, match="no longer present"):
        plan_selection([supported], ["missing"])
    with pytest.raises(SelectionPlanError, match="distinct"):
        plan_selection([supported], [supported.stable_id, supported.stable_id])


def test_planner_fails_closed_when_approved_port_range_is_exhausted():
    app = _app("finance", "finance", "finance-rag")
    with pytest.raises(SelectionPlanError, match="No approved"):
        plan_selection([app], [app.stable_id], occupied_ports=[19000], port_start=19000, port_end=19000)


def test_connector_plan_requires_explicit_selection_and_changes_nothing(monkeypatch, capsys):
    from apps.gateway.accessproof_gateway import customer_connect

    rows = [{"Names": "finance-rag", "Image": "rag:1", "Ports": "127.0.0.1:18090->8090/tcp", "Labels": {
        "com.docker.compose.project": "finance", "com.docker.compose.service": "finance-rag",
        "com.accessproof.gateway.contract": "accessproof.gateway/v1",
        "com.accessproof.gateway.enforces": "attested-retrieval-and-buffered-output",
        "com.accessproof.gateway.route_env": "ACCESSPROOF_CHAT_URL",
    }}]
    monkeypatch.setattr(customer_connect, "docker_inventory", lambda: rows)
    discovered = customer_connect.discover(rows)
    assert customer_connect.main(["--plan", "--select", discovered[0].stable_id]) == 0
    output = capsys.readouterr().out
    assert '"gateway_service"' in output
    assert '"listen_port": 18091' in output
