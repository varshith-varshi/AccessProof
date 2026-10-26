from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import asyncio
import json
from packages.domain.models import Principal
from packages.domain.scenario import PollingPolicy, ScenarioDefinition, StabilityPolicy
from packages.reporting.report import build_manifest
from packages.test_engine.clock import SimulatedClock
from packages.test_engine.engine import PermissionRegressionEngine
from connectors.mock_source.adapter import MockSourceAdapter
from connectors.mock_source.target import MockRagTarget


async def main() -> None:
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock, source_mutation_delay_seconds=0)
    target = MockRagTarget(source=source, clock=clock, stale_acl_seconds=90)
    engine = PermissionRegressionEngine(source, target, clock=clock)
    scenario = ScenarioDefinition(
        name="group_membership_revocation_demo",
        maximum_slo_seconds=30,
        timeout_seconds=180,
        polling=PollingPolicy(
            initial_interval_seconds=10, maximum_interval_seconds=10, backoff_multiplier=1
        ),
        stability=StabilityPolicy(
            required_clean_observations=3, required_clean_duration_seconds=20
        ),
    )
    result = await engine.run_revocation(
        allowed=Principal(external_id="alice", email="alice@example.invalid"),
        denied_control=Principal(external_id="bob", email="bob@example.invalid"),
        scenario=scenario,
    )
    manifest = build_manifest(result)
    print(
        json.dumps(
            {
                "outcome": result.outcome.value,
                "stable_propagation_latency_seconds": result.metrics.stable_propagation_latency_seconds,
                "expected_slo_seconds": result.expected_slo_seconds,
                "reason": result.reason,
                "report_sha256": manifest["report_sha256"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
