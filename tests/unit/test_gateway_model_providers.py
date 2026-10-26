"""Native Claude/Gemini and explicit custom LLM adapter security regression."""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from apps.gateway.accessproof_gateway.app import GatewaySettings, create_app
from apps.gateway.accessproof_gateway.installer import InstallationError, InstallationSpec, private_environment
from apps.gateway.accessproof_gateway.model_adapters import ModelProtocolError
from packages.rag_sdk import (
    ContentBinding, SourceAttestationSigner, SourceAttestationVerifier,
)


MODELS = {
    "openai-compatible": ("https://example-model.internal/v1/chat/completions", None, None),
    "anthropic": ("https://api.anthropic.com/v1/messages", "claude-sonnet-4-5", "synthetic-provider-secret"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
               "gemini-2.5-flash", "synthetic-provider-secret"),
}


def _setup(
    protocol: str, *, layer1: str = "allow", layer2: str = "allow",
    model_payload: Any = None, adapter: Any = None,
) -> tuple[TestClient, list[httpx.Request], list[httpx.Request]]:
    private = Ed25519PrivateKey.generate()
    verifier = SourceAttestationVerifier(
        tenant_id="tenant-a", trusted_keys={"ingester": private.public_key()},
    )
    url, model, secret = MODELS.get(protocol, (
        "https://custom-model.internal/infer", "customer-private", "synthetic-provider-secret",
    ))
    settings = GatewaySettings(
        guard_url="https://guard.test", model_url=url,
        application_id="finance-rag", tenant_id="tenant-a",
        verifier=verifier, model_provider=protocol,
        model_name=model, model_bearer_token=secret,
        max_response_bytes=200_000,
    )
    guard_seen: list[httpx.Request] = []
    model_seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "guard.test":
            guard_seen.append(request)
            if request.url.path.endswith("filter-resources"):
                resources = json.loads(request.content)["resources"]
                return httpx.Response(200, json={
                    "decision_id": "l1", "decision": layer1, "mode": "protect",
                    "allowed": ([{"source_id": i["source_id"], "resource_id": i["resource_id"],
                                  "chunk_ids": i["chunk_ids"]}
                                 for i in resources] if layer1 == "allow" else []),
                    "denied": [], "unknown": [],
                })
            if request.url.path.endswith("check-output"):
                return httpx.Response(200, json={"decision": layer2, "reason": "TEST"})
        else:
            model_seen.append(request)
            if model_payload is not None:
                return httpx.Response(200, json=model_payload)
            if protocol == "anthropic":
                return httpx.Response(200, json={
                    "type": "message", "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": "NATIVE_CLAUDE_SAFE"}],
                })
            if protocol == "gemini":
                return httpx.Response(200, json={
                    "candidates": [{
                        "finishReason": "STOP",
                        "content": {"parts": [{"text": "NATIVE_GEMINI_SAFE"}]},
                    }],
                })
            return httpx.Response(200, json={
                "choices": [{"message": {"content": "CUSTOM_SAFE"}, "finish_reason": "stop"}],
            })
        raise AssertionError(f"Unexpected request to {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    app = create_app(settings, client=client, model_adapter=adapter)
    app.state.signer = SourceAttestationSigner(
        key_id="ingester", private_key=private,
    )
    return TestClient(app), guard_seen, model_seen


def _resource(client: TestClient, *, content: str = "APPROVED_DOCUMENT") -> dict[str, Any]:
    binding = ContentBinding(
        tenant_id="tenant-a", application_id="finance-rag",
        source_id="drive-1", resource_id="document-1",
        chunk_id="chunk-1", content_version="v1", content=content,
    )
    return {
        "source_id": binding.source_id, "resource_id": binding.resource_id,
        "chunk_id": binding.chunk_id, "content_version": binding.content_version,
        "content": content, "content_attestation": client.app.state.signer.issue(binding),
    }


def _chat(client: TestClient, *, stream: bool = False, resources: list[dict] | None = None) -> httpx.Response:
    return client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer employee-verified-token"},
        json={
            "application_id": "finance-rag", "employee_question": "Summarize",
            "employee_conversation": [{"role": "user", "content": "I asked something earlier"}],
            "retrieved_resources": resources if resources is not None else [_resource(client)],
            "stream": stream,
        },
    )


@pytest.mark.parametrize("protocol", ["anthropic", "gemini"])
def test_native_provider_receives_only_guard_authorized_context(protocol):
    client, guard_seen, model_seen = _setup(protocol)
    response = _chat(client)
    assert response.status_code == 200, response.text
    assert response.json()["choices"][0]["message"]["content"] == (
        "NATIVE_CLAUDE_SAFE" if protocol == "anthropic" else "NATIVE_GEMINI_SAFE"
    )
    assert len(guard_seen) == 2
    assert len(model_seen) == 1
    sent = model_seen[0]
    payload = json.loads(sent.content)
    assert "APPROVED_DOCUMENT" in json.dumps(payload)
    assert "employee-verified-token" not in json.dumps(payload)
    assert "employee-verified-token" not in str(dict(sent.headers))
    assert "stream" not in payload or payload["stream"] is False
    if protocol == "anthropic":
        assert sent.url.path == "/v1/messages"
        assert sent.headers["x-api-key"] == "synthetic-provider-secret"
        assert sent.headers["anthropic-version"] == "2023-06-01"
        assert "authorization" not in sent.headers
        assert payload["model"] == "claude-sonnet-4-5"
        assert payload["max_tokens"] > 0
        assert all(t["role"] == "user" for t in payload["messages"])
        assert payload["system"].startswith("Use only authenticated")
        assert "AUTHORIZED ENTERPRISE CONTEXT" in json.dumps(payload["messages"])
        assert "AUTHORIZED ENTERPRISE CONTEXT" not in payload["system"]
    else:
        assert sent.headers["x-goog-api-key"] == "synthetic-provider-secret"
        assert "authorization" not in sent.headers
        assert "systemInstruction" in payload
        assert all(t["role"] == "user" for t in payload["contents"])
        assert "AUTHORIZED ENTERPRISE CONTEXT" in json.dumps(payload["contents"])
        assert "AUTHORIZED ENTERPRISE CONTEXT" not in json.dumps(payload["systemInstruction"])


@pytest.mark.parametrize("protocol", ["anthropic", "gemini"])
def test_native_provider_no_model_call_when_layer1_denies_or_attestation_forged(protocol):
    client, _, model_seen = _setup(protocol, layer1="block")
    response = _chat(client)
    assert response.status_code == 403
    assert model_seen == []
    client2, _, model_seen2 = _setup(protocol)
    forged = _resource(client2)
    forged["content"] = "FORGED_ENTERPRISE_SECRET"
    result = _chat(client2, resources=[forged])
    assert result.status_code == 503
    assert model_seen2 == []
    assert "FORGED_ENTERPRISE_SECRET" not in result.text


@pytest.mark.parametrize("protocol", ["anthropic", "gemini"])
@pytest.mark.parametrize("stream", [False, True])
def test_native_provider_never_releases_model_output_when_layer2_denies(protocol, stream):
    client, _, model_seen = _setup(protocol, layer2="block")
    response = _chat(client, stream=stream)
    assert response.status_code == 503
    assert "NATIVE_CLAUDE_SAFE" not in response.text
    assert "NATIVE_GEMINI_SAFE" not in response.text
    assert "text/event-stream" not in response.headers.get("content-type", "")
    assert len(model_seen) == 1


@pytest.mark.parametrize("protocol,payload", [
    ("anthropic", {"type": "message", "stop_reason": "tool_use",
                   "content": [{"type": "tool_use", "id": "call", "name": "download", "input": {}}]}),
    ("anthropic", {"type": "message", "stop_reason": "max_tokens",
                   "content": [{"type": "text", "text": "CUT_OFF_UNSAFE"}]}),
    ("anthropic", {"type": "message", "stop_reason": "end_turn",
                   "content": [{"type": "text", "text": "OK"},
                               {"type": "tool_use", "name": "secret"}]}),
    ("gemini", {"candidates": [{"finishReason": "MAX_TOKENS",
                               "content": {"parts": [{"text": "UNSAFE_PARTIAL"}]}}]}),
    ("gemini", {"candidates": [{"finishReason": "STOP",
                               "content": {"parts": [{"functionCall": {"name": "export"}}]}}]}),
    ("gemini", {"promptFeedback": {"blockReason": "SAFETY"}, "candidates": []}),
    ("gemini", {"candidates": [{"finishReason": "STOP",
                               "content": {"parts": [{"text": "OK"}, {"text": "SECOND", "thought": True}]}}]}),
])
def test_native_provider_rejects_untrusted_tool_calls_partial_outputs_and_bad_frames(protocol, payload):
    client, _, model_seen = _setup(protocol, model_payload=payload)
    response = _chat(client)
    assert response.status_code == 503
    assert "OK" not in response.text
    assert "CUT_OFF_UNSAFE" not in response.text
    assert len(model_seen) == 1


@pytest.mark.parametrize("protocol", ["anthropic", "gemini"])
def test_native_provider_buffered_sse_starts_after_layer2_passes(protocol):
    client, guard_seen, _ = _setup(protocol)
    response = _chat(client, stream=True)
    assert response.status_code == 200
    assert response.text.endswith("data: [DONE]\n\n")
    assert response.headers["content-type"].startswith("text/event-stream")
    assert len(guard_seen) == 2


@pytest.mark.parametrize("protocol,url,model,api_key", [
    ("anthropic", "https://evil.example/v1/messages", "claude-sonnet-4-5", "key"),
    ("anthropic", "http://api.anthropic.com/v1/messages", "claude-sonnet-4-5", "key"),
    ("anthropic", "https://api.anthropic.com/v1/messages", None, "key"),
    ("anthropic", "https://api.anthropic.com/v1/messages", "claude-sonnet-4-5", None),
    ("gemini", "https://evil.example/v1beta/models/gemini:generateContent", None, "key"),
    ("gemini", "https://generativelanguage.googleapis.com/v1beta/models/gemini:generateContent", "other-model", "key"),
    ("gemini", "https://generativelanguage.googleapis.com/v1beta/models/%2F:generateContent", None, "key"),
    ("gemini", "https://generativelanguage.googleapis.com/v1beta/models/gemini:generateContent", None, None),
    ("proprietary", "https://example.test/model", None, None),
])
def test_native_provider_invalid_configuration_fails_at_startup(protocol, url, model, api_key):
    private = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError):
        GatewaySettings(
            guard_url="https://guard.test", model_url=url,
            application_id="app", tenant_id="t",
            verifier=SourceAttestationVerifier(tenant_id="t", trusted_keys={"k": private.public_key()}),
            model_provider=protocol, model_name=model, model_bearer_token=api_key,
        )


def test_explicit_proprietary_adapter_registration_requires_installed_code():
    class CustomerModel:
        def validate(self, model_url, model_name, api_key):
            assert model_url == "https://custom-model.internal/infer"

        def request(self, messages, model_name):
            assert len(messages) >= 3
            return {"query": messages[-1]["content"], "context": messages[-2]["content"]}

        def headers(self, api_key):
            return {"x-customer-token": api_key}

        def extract_text(self, payload):
            if set(payload) != {"answer"} or not isinstance(payload["answer"], str):
                raise ModelProtocolError("CUSTOM_MODEL_RESPONSE_INVALID")
            return payload["answer"]

    adapter = CustomerModel()
    client, _, model_seen = _setup("custom", adapter=adapter)
    # _setup default returns OpenAI-shaped data, custom adapter rejects it,
    # so verify fail-closed instead of quietly pretending format compatibility.
    response = _chat(client)
    assert response.status_code == 503
    assert len(model_seen) == 1


def test_native_installer_serializes_api_provider_and_rejects_unknown():
    private = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import base64
    key = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    spec = InstallationSpec.parse({
        "tenant_id": "t", "application_id": "app", "rag_service": "rag",
        "guard_url": "http://guard:8080",
        "model_url": "https://api.anthropic.com/v1/messages",
        "model_provider": "anthropic", "model_name": "claude-sonnet-4-5",
        "model_token_env": "ANTHROPIC_CUSTOMER_KEY",
        "trusted_public_keys": {"k": key},
    })
    env = private_environment(spec, {"ANTHROPIC_CUSTOMER_KEY": "synthetic-key$with-dollar"})
    assert "ACCESSPROOF_GATEWAY_MODEL_PROVIDER=anthropic" in env
    assert "ACCESSPROOF_GATEWAY_MODEL_BEARER_TOKEN=synthetic-key$with-dollar" in env
    with pytest.raises(InstallationError):
        InstallationSpec.parse({
            "tenant_id": "t", "application_id": "app", "rag_service": "rag",
            "guard_url": "http://guard:8080",
            "model_url": "https://api.anthropic.com/v1/messages",
            "model_provider": "anthropic",
            "model_name": "claude-sonnet-4-5",
            "trusted_public_keys": {"k": key},
        })


def test_custom_requires_explicit_adapter_and_disallows_builtin_override():
    private = Ed25519PrivateKey.generate()
    verifier = SourceAttestationVerifier(
        tenant_id="t", trusted_keys={"k": private.public_key()},
    )
    kwargs = dict(
        guard_url="https://guard.test", model_url="https://custom.example/infer",
        application_id="app", tenant_id="t", verifier=verifier,
    )
    with pytest.raises(ModelProtocolError, match="CUSTOM_MODEL_ADAPTER_REQUIRED"):
        create_app(GatewaySettings(**kwargs, model_provider="custom"))
    with pytest.raises(ModelProtocolError, match="MODEL_ADAPTER_PROVIDER_MISMATCH"):
        create_app(GatewaySettings(**kwargs), model_adapter=object())


def test_explicit_custom_adapter_can_complete_native_contract_without_openai_format():
    class ProprietaryModel:
        def validate(self, url, model_name, api_key):
            assert url == "https://custom-model.internal/infer"

        def request(self, messages, model_name):
            # Source content is only present AFTER Layer 1.
            trusted_data_turns = [
                item["content"] for item in messages
                if item["role"] == "user"
                and item["content"].startswith("AUTHORIZED ENTERPRISE CONTEXT")
            ]
            assert len(trusted_data_turns) == 1
            return {"prompt": messages[-1]["content"],
                    "retrieval_context": trusted_data_turns[0]}

        def headers(self, api_key):
            return {"x-internal-model-key": api_key or ""}

        def extract_text(self, payload):
            if (not isinstance(payload, dict) or set(payload) != {"answer"}
                    or not isinstance(payload["answer"], str)):
                raise ModelProtocolError("CUSTOM_MODEL_BAD_RESPONSE")
            return payload["answer"]

    private = Ed25519PrivateKey.generate()
    verifier = SourceAttestationVerifier(
        tenant_id="tenant-a", trusted_keys={"ingester": private.public_key()},
    )
    settings = GatewaySettings(
        guard_url="https://guard.test", model_url="https://custom-model.internal/infer",
        application_id="finance-rag", tenant_id="tenant-a",
        verifier=verifier, model_provider="custom",
        model_bearer_token="internal-key",
    )
    requests = []

    def handler(req):
        if req.url.host == "custom-model.internal":
            requests.append(req)
            assert req.headers["x-internal-model-key"] == "internal-key"
            assert "employee-verified-token" not in req.content.decode()
            assert "APPROVED_DOCUMENT" in req.content.decode()
            return httpx.Response(200, json={"answer": "PRIVATE_MODEL_ANSWER"})
        if req.url.path.endswith("filter-resources"):
            resources = json.loads(req.content)["resources"]
            return httpx.Response(200, json={
                "decision_id": "layer1", "decision": "allow", "mode": "protect",
                "allowed": [{"source_id": item["source_id"], "resource_id": item["resource_id"],
                             "chunk_ids": item["chunk_ids"]} for item in resources],
                "denied": [], "unknown": [],
            })
        if req.url.path.endswith("check-output"):
            return httpx.Response(200, json={"decision": "allow", "reason": "TEST"})
        raise AssertionError(req.url)

    app = create_app(
        settings,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        model_adapter=ProprietaryModel(),
    )
    app.state.signer = SourceAttestationSigner(key_id="ingester", private_key=private)
    c = TestClient(app)
    result = _chat(c)
    assert result.status_code == 200
    assert result.json()["choices"][0]["message"]["content"] == "PRIVATE_MODEL_ANSWER"
    assert len(requests) == 1
