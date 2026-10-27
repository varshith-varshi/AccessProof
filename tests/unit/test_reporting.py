import pytest
from packages.domain.models import Principal, RunOutcome
from packages.domain.scenario import PollingPolicy, ScenarioDefinition, StabilityPolicy
from packages.test_engine.clock import SimulatedClock
from packages.test_engine.engine import PermissionRegressionEngine
from connectors.mock_source.adapter import MockSourceAdapter
from connectors.mock_source.target import MockRagTarget
from packages.reporting.report import (
    build_manifest,
    render_html,
    render_junit,
    render_pdf_bytes,
    render_sarif,
)


@pytest.mark.asyncio
async def test_report_formats():
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock)
    target = MockRagTarget(source=source, clock=clock, stale_acl_seconds=30)
    scenario = ScenarioDefinition(
        name="report_test",
        maximum_slo_seconds=10,
        timeout_seconds=100,
        polling=PollingPolicy(
            initial_interval_seconds=10, maximum_interval_seconds=10, backoff_multiplier=1
        ),
        stability=StabilityPolicy(
            required_clean_observations=2, required_clean_duration_seconds=10
        ),
    )
    result = await PermissionRegressionEngine(source, target, clock=clock).run_revocation(
        allowed=Principal("alice"), denied_control=Principal("bob"), scenario=scenario
    )
    assert result.outcome is RunOutcome.FAIL
    manifest = build_manifest(result)
    assert len(manifest["report_sha256"]) == 64
    assert "AccessProof Report" in render_html(result)
    assert "testsuite" in render_junit(result)
    assert render_sarif(result)["version"] == "2.1.0"
    assert render_pdf_bytes(result).startswith(b"%PDF")


def test_junit_distinguishes_internal_error_from_inconclusive():
    from uuid import uuid4
    from packages.domain.models import EngineResult, PropagationMetrics

    error_result = EngineResult(
        run_id=uuid4(),
        outcome=RunOutcome.ERROR,
        metrics=PropagationMetrics(),
        observations=[],
        timeline=[],
        source_ground_truth="UNKNOWN",
        expected_slo_seconds=60,
        reason="internal failure",
    )
    xml = render_junit(error_result)
    assert "<error" in xml and "<skipped" not in xml


def test_sarif_payload_helper_matches_fail_semantics():
    from packages.reporting.report import render_sarif_payload

    payload = {
        "run_id": "r1",
        "outcome": "FAIL",
        "reason": "too slow",
        "expected_slo_seconds": 60,
        "derived": {"stable_propagation_latency_seconds": 120},
        "diagnostic": {"boundary": "DOWNSTREAM_OF_SOURCE_AUTHORIZATION"},
    }
    sarif = render_sarif_payload(payload)
    assert sarif["runs"][0]["results"][0]["ruleId"] == "AP001"
    assert (
        sarif["runs"][0]["results"][0]["properties"]["failureBoundary"]
        == "DOWNSTREAM_OF_SOURCE_AUTHORIZATION"
    )
