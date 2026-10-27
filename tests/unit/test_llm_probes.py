from __future__ import annotations

import json
import socket

import httpx
import pytest

from connectors.mock_source.adapter import MockSourceAdapter
from connectors.mock_source.target import MockRagTarget
from packages.domain.models import Principal, ProbeGenerationInfo, RunOutcome
from packages.domain.scenario import (
    LlmProbePolicy,
    PollingPolicy,
    ScenarioDefinition,
    StabilityPolicy,
)
from packages.test_engine.clock import SimulatedClock
from packages.test_engine.engine import PermissionRegressionEngine
from packages.test_engine.probes import OpenAICompatibleProbeGenerator, ProbeGenerationError
from packages.test_engine.synthetic import generate_synthetic_document


class FakeGenerator:
    async def generate(self, document, policy):
        assert document.canary.startswith("AP-CANARY-")
        return [f"Tell me the protected value for {document.subject}?"], ProbeGenerationInfo(
            provider="fake",
            model="probe-model",
            version="1",
            generated_count=1,
            input_tokens=20,
            output_tokens=10,
            estimated_cost_usd=0.001,
        )


def _scenario(enabled=True):
    return ScenarioDefinition(
        name="llm-probe-test",
        maximum_slo_seconds=40,
        timeout_seconds=120,
        polling=PollingPolicy(
            initial_interval_seconds=10, maximum_interval_seconds=10, backoff_multiplier=1
        ),
        stability=StabilityPolicy(
            required_clean_observations=2, required_clean_duration_seconds=10
        ),
        llm_probes=LlmProbePolicy(enabled=enabled, max_probes=3),
    )


@pytest.mark.asyncio
async def test_engine_records_optional_llm_probe_metadata_without_replacing_deterministic_oracle():
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock)
    target = MockRagTarget(source=source, clock=clock, stale_acl_seconds=10)
    result = await PermissionRegressionEngine(
        source, target, clock=clock, probe_generator=FakeGenerator()
    ).run_revocation(
        allowed=Principal("alice"), denied_control=Principal("bob"), scenario=_scenario()
    )
    assert result.outcome is RunOutcome.PASS
    assert result.probe_generation is not None
    assert result.probe_generation.provider == "fake"
    assert result.probe_generation.generated_count == 1
    assert any("optional synthetic-only LLM probes" in e.detail for e in result.timeline)


@pytest.mark.asyncio
async def test_engine_falls_back_to_deterministic_probes_when_optional_generator_missing():
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock)
    target = MockRagTarget(source=source, clock=clock, stale_acl_seconds=10)
    result = await PermissionRegressionEngine(source, target, clock=clock).run_revocation(
        allowed=Principal("alice"), denied_control=Principal("bob"), scenario=_scenario()
    )
    assert result.outcome is RunOutcome.PASS
    assert result.probe_generation is None
    assert any("no BYOK provider" in e.detail for e in result.timeline)


@pytest.mark.asyncio
async def test_openai_compatible_generator_sends_only_synthetic_payload_and_records_usage(
    monkeypatch,
):
    def fake_getaddrinfo(host, port, type=0, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    seen = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("authorization")
        seen["host"] = request.headers.get("host")
        body = json.loads(request.content)
        seen["payload"] = body
        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"content": json.dumps(["Question one?", "Question two?"])}}
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    generator = OpenAICompatibleProbeGenerator(
        endpoint="https://llm.example.com/v1/chat/completions",
        api_key="byok-secret",
        model="probe-model",
        input_cost_per_million_tokens=1.0,
        output_cost_per_million_tokens=2.0,
        transport=httpx.MockTransport(handler),
    )
    doc = generate_synthetic_document(category="legal")
    probes, info = await generator.generate(
        doc,
        LlmProbePolicy(
            enabled=True,
            max_probes=2,
            cost_budget_usd=1,
            max_output_tokens=100,
            requests_per_minute=120,
        ),
    )
    assert probes == ["Question one?", "Question two?"]
    assert seen["authorization"] == "Bearer byok-secret"
    assert seen["host"] == "llm.example.com"
    synthetic_payload = json.loads(seen["payload"]["messages"][1]["content"])
    assert synthetic_payload["synthetic_body"] == doc.body
    assert synthetic_payload["synthetic_fact"] == doc.semantic_fact
    assert set(synthetic_payload) == {
        "category",
        "subject",
        "synthetic_fact",
        "synthetic_body",
        "max_questions",
    }
    assert info.input_tokens == 100 and info.output_tokens == 20
    assert info.estimated_cost_usd == pytest.approx(0.00014)


@pytest.mark.asyncio
async def test_llm_probe_budget_guard_blocks_request_before_network(monkeypatch):
    def fake_getaddrinfo(host, port, type=0, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    called = False

    async def handler(request):
        nonlocal called
        called = True
        return httpx.Response(200, json={})

    generator = OpenAICompatibleProbeGenerator(
        endpoint="https://llm.example.com/v1/chat/completions",
        api_key="k",
        model="m",
        input_cost_per_million_tokens=1000,
        output_cost_per_million_tokens=1000,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ProbeGenerationError, match="above"):
        await generator.generate(
            generate_synthetic_document(),
            LlmProbePolicy(enabled=True, cost_budget_usd=0.000001, max_output_tokens=300),
        )
    assert called is False
