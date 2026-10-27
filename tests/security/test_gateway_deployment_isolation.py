"""Regression contract for the read-only Gateway topology assessor."""
from __future__ import annotations

from copy import deepcopy

from scripts.validate_gateway_route_isolation import examine_topology
from tests.unit.test_gateway_network_boundary import _compose


def _run(config):
    return examine_topology(
        config, rag_service="customer-rag",
        gateway_service="accessproof-gateway",
        model_url="http://model:8000/v1/chat/completions",
        expected_route_env="ACCESSPROOF_CHAT_URL",
        model_provider="openai-compatible",
    )


def test_explicit_isolated_reference_topology_is_only_static_pass():
    result = _run(_compose())
    assert result["result"] == "STATIC_REFERENCE_TOPOLOGY_PASSED"
    assert result["customer_protection_certified"] is False
    assert result["runtime_probe_required"] is True


def test_flat_default_bridge_fails_static_gateway_isolation():
    config = deepcopy(_compose())
    config["networks"]["rag-isolated"] = {"internal": False}
    result = _run(config)
    assert result["result"] == "BLOCKED_UNVERIFIED_TOPOLOGY"
    assert result["customer_protection_certified"] is False


def test_host_network_override_bypasses_topology_certification():
    config = deepcopy(_compose())
    config["services"]["customer-rag"]["network_mode"] = "host"
    result = _run(config)
    assert result["result"] == "BLOCKED_UNVERIFIED_TOPOLOGY"


def test_relay_sidecar_cannot_bridge_rag_to_model():
    config = deepcopy(_compose())
    config["services"]["hidden-relay"] = {
        "networks": ["rag-isolated", "model-private"],
    }
    result = _run(config)
    assert result["result"] == "BLOCKED_UNVERIFIED_TOPOLOGY"


def test_wrong_rag_route_and_unset_model_both_block():
    config = deepcopy(_compose())
    config["services"]["customer-rag"]["environment"][
        "ACCESSPROOF_CHAT_URL"
    ] = "http://model:8000/v1/chat/completions"
    assert _run(config)["result"] == "BLOCKED_UNVERIFIED_TOPOLOGY"
    assert examine_topology(
        _compose(), rag_service="customer-rag",
        gateway_service="accessproof-gateway", model_url="",
        expected_route_env="ACCESSPROOF_CHAT_URL",
        model_provider="openai-compatible",
    )["result"] == "BLOCKED_UNVERIFIED_TOPOLOGY"


def test_repository_isolated_gateway_compose_template_preserves_boundary():
    from pathlib import Path

    import yaml

    from apps.gateway.accessproof_gateway.network_boundary import (
        verify_reference_compose_isolation,
    )

    root = Path(__file__).resolve().parents[2]
    template = yaml.safe_load(
        (root / "docker-compose.gateway-isolated-reference.yml").read_text()
    )
    verdict = verify_reference_compose_isolation(
        template,
        rag_service="customer-rag", gateway_service="accessproof-gateway",
        model_url="http://model:8000/v1/chat/completions",
        guard_url="http://guard:8080",
        expected_route_env="ACCESSPROOF_CHAT_URL",
    )
    assert verdict["static_egress_isolated"] is True
    assert verdict["customer_deployment_certified"] is False

    from apps.gateway.accessproof_gateway.network_boundary import (
        NetworkBoundaryError,
    )

    template["networks"]["rag-isolated"]["internal"] = False
    import pytest

    with pytest.raises(NetworkBoundaryError):
        verify_reference_compose_isolation(
            template,
            rag_service="customer-rag", gateway_service="accessproof-gateway",
            model_url="http://model:8000/v1/chat/completions",
            guard_url="http://guard:8080",
            expected_route_env="ACCESSPROOF_CHAT_URL",
        )
