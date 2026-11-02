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
