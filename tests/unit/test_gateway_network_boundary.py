from copy import deepcopy

import pytest

from apps.gateway.accessproof_gateway.network_boundary import (
    NetworkBoundaryError, verify_reference_compose_isolation,
)


def _compose():
    return {
        "networks": {"rag-isolated": {"internal": True}, "model-private": {"internal": True},
                     "accessproof-gateway-host": {"internal": False}},
        "services": {
            "customer-rag": {
                "image": "reference-rag@sha256:" + "a" * 64,
                "networks": ["rag-isolated"],
                "environment": {
                    "ACCESSPROOF_CHAT_URL": "http://accessproof-gateway:8090/v1/chat/completions"
                },
            },
            "accessproof-gateway": {
                "image": "accessproof-gateway@sha256:" + "b" * 64,
                "read_only": True, "cap_drop": ["ALL"],
                "networks": ["rag-isolated", "model-private", "accessproof-gateway-host"],
            },
            "model": {
                "image": "reference-model@sha256:" + "c" * 64,
                "networks": ["model-private"],
            },
        },
    }


def _check(config):
    return verify_reference_compose_isolation(
        config, rag_service="customer-rag",
        model_url="http://model:8000/v1/chat/completions",
        expected_route_env="ACCESSPROOF_CHAT_URL",
    )


def test_reference_only_supports_provably_restricted_compose_network():
    report = _check(_compose())
    assert report["static_egress_isolated"]
    assert report["customer_deployment_certified"] is False


@pytest.mark.parametrize("mutation", [
    lambda c: c["services"]["customer-rag"]["networks"].append("model-private"),
    lambda c: c["networks"]["rag-isolated"].update(internal=False),
    lambda c: c["services"]["model"].update(ports=["127.0.0.1:8000:8000"]),
    lambda c: c["services"]["accessproof-gateway"].update(read_only=False),
    lambda c: c["services"]["customer-rag"].update(network_mode="host"),
    lambda c: c["services"]["customer-rag"].update(extra_hosts=["model:127.0.0.1"]),
    lambda c: c["services"]["customer-rag"].update(volumes=["/var/run/docker.sock:/var/run/docker.sock"]),
    lambda c: c["services"]["customer-rag"]["environment"].update(ACCESSPROOF_CHAT_URL="http://model:8000"),
])
def test_insecure_bypass_topology_rejected(mutation):
    config = deepcopy(_compose())
    mutation(config)
    with pytest.raises(NetworkBoundaryError):
        _check(config)


def test_external_model_api_cannot_claim_reference_network_isolation():
    with pytest.raises(NetworkBoundaryError, match="in-stack model"):
        verify_reference_compose_isolation(
            _compose(), rag_service="customer-rag",
            model_url="https://api.openai.com/v1/chat/completions",
            expected_route_env="ACCESSPROOF_CHAT_URL",
        )


@pytest.mark.parametrize("provider,url", [
    ("anthropic", "https://api.anthropic.com/v1/messages"),
    ("gemini", "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"),
])
def test_native_cloud_endpoint_static_reference_rag_cannot_reach_internet(provider, url):
    # The Gateway alone owns a non-internal bridge for outbound HTTPS.
    # The actual RAG is limited to its private internal network.
    config = _compose()
    del config["services"]["model"]
    config["services"]["accessproof-gateway"]["networks"].remove("model-private")
    result = verify_reference_compose_isolation(
        config, rag_service="customer-rag", model_provider=provider,
        model_url=url, expected_route_env="ACCESSPROOF_CHAT_URL",
    )
    assert result["static_egress_isolated"]
    assert result["external_model_endpoint"]
    assert result["model_service"] is None
    assert not result["customer_deployment_certified"]


@pytest.mark.parametrize("mutation", [
    lambda c: c["services"]["customer-rag"]["networks"].append("accessproof-gateway-host"),
    lambda c: c["networks"]["rag-isolated"].update(internal=False),
    lambda c: c["services"]["customer-rag"].update(network_mode="host"),
    lambda c: c["services"]["customer-rag"].update(privileged=True),
    lambda c: c["services"]["customer-rag"].update(extra_hosts=["api.anthropic.com:127.0.0.1"]),
])
def test_native_cloud_rag_bypass_networks_rejected(mutation):
    config = _compose()
    del config["services"]["model"]
    config["services"]["accessproof-gateway"]["networks"].remove("model-private")
    mutation(config)
    with pytest.raises(NetworkBoundaryError):
        verify_reference_compose_isolation(
            config, rag_service="customer-rag", model_provider="anthropic",
            model_url="https://api.anthropic.com/v1/messages",
            expected_route_env="ACCESSPROOF_CHAT_URL",
        )


@pytest.mark.parametrize("provider,url", [
    ("anthropic", "https://evil.example/v1/messages"),
    ("gemini", "https://evil.example/v1beta/models/gemini:generateContent"),
])
def test_native_cloud_requires_official_https_host(provider, url):
    config = _compose()
    del config["services"]["model"]
    config["services"]["accessproof-gateway"]["networks"].remove("model-private")
    with pytest.raises(NetworkBoundaryError):
        verify_reference_compose_isolation(
            config, rag_service="customer-rag", model_provider=provider,
            model_url=url, expected_route_env="ACCESSPROOF_CHAT_URL",
        )



def test_docker_compose_omitted_false_internal_is_a_valid_gateway_host_bridge():
    config = _compose()
    del config["networks"]["accessproof-gateway-host"]["internal"]
    report = _check(config)
    assert report["static_egress_isolated"]
    config["networks"]["accessproof-gateway-host"]["internal"] = True
    with pytest.raises(NetworkBoundaryError):
        _check(config)
