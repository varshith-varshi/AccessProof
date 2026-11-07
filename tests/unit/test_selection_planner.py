from __future__ import annotations

import pytest

from apps.gateway.accessproof_gateway.application_discovery import DiscoveredApplication
from apps.gateway.accessproof_gateway.selection_planner import SelectionPlanError, plan_selection


def _app(stable_id: str, project: str, service: str, state: str = "SUPPORTED") -> DiscoveredApplication:
    return DiscoveredApplication(stable_id, service, project, service, "rag:1", state, "test")


def test_one_selected_rag_is_planned_and_others_left_untouched():
    finance = _app("host-finance", "finance", "rag")
    hr = _app("host-hr", "hr", "rag")
    ignored = _app("host-sales", "sales", "rag", "REQUIRES_INTEGRATION")
    plans = plan_selection([finance, hr, ignored], [finance.stable_id], occupied_ports=[18090])
    assert len(plans) == 1
    assert plans[0].stable_id == "host-finance"
    assert (plans[0].compose_project, plans[0].rag_service, plans[0].listen_port) == (
        "finance", "rag", 8090,
    )
    assert plans[0].gateway_service == "accessproof-gateway"
    assert "hr" not in plans[0].gateway_service


def test_multi_select_is_rejected_even_if_all_chatbots_are_supported():
    finance = _app("host-finance", "finance", "rag")
    hr = _app("host-hr", "hr", "rag")
    with pytest.raises(SelectionPlanError, match="exactly one"):
        plan_selection([finance, hr], [finance.stable_id, hr.stable_id])


def test_planner_rejects_unselected_stale_or_unsupported_apps():
    supported = _app("supported", "finance", "finance-rag")
    unsupported = _app("unsupported", "sales", "sales-rag", "REQUIRES_INTEGRATION")
    with pytest.raises(SelectionPlanError, match="adapter contract"):
        plan_selection([supported, unsupported], [unsupported.stable_id])
    with pytest.raises(SelectionPlanError, match="no longer present"):
        plan_selection([supported], ["missing"])
    with pytest.raises(SelectionPlanError, match="exactly one"):
        plan_selection([supported], [supported.stable_id, supported.stable_id])


def test_planner_allocates_a_separate_loopback_port_for_another_gateway():
    app = _app("finance", "finance", "finance-rag")
    plan = plan_selection([app], [app.stable_id], occupied_ports=[8090])[0]
    assert plan.listen_port == 18090
    plan = plan_selection([app], [app.stable_id], occupied_ports=[8090, 18090])[0]
    assert plan.listen_port == 18091


def test_planner_fails_closed_when_approved_port_range_is_exhausted():
    app = _app("finance", "finance", "finance-rag")
    with pytest.raises(SelectionPlanError, match="approved Gateway loopback ports"):
        plan_selection([app], [app.stable_id], occupied_ports=[8090, *range(18090, 18110)])


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
    assert '"listen_port": 8090' in output


def test_reject_ambiguous_duplicate_discovery_identities() -> None:
    a = _app("same-id", "finance", "rag")
    b = _app("same-id", "hr", "rag")
    with pytest.raises(SelectionPlanError, match="duplicate"):
        plan_selection([a, b], ["same-id"])


def test_select_without_pairing_does_not_touch_docker(monkeypatch, capsys):
    from apps.gateway.accessproof_gateway import customer_connect
    monkeypatch.setattr(customer_connect, "docker_inventory",
                        lambda: (_ for _ in ()).throw(AssertionError("unexpected Docker discovery")))
    assert customer_connect.main(["--select", "host-app-any"]) == 1
    assert "pairing file" in capsys.readouterr().err.lower()
