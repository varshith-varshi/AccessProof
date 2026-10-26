import asyncio

from connectors.mock_source.adapter import MockSourceAdapter
from connectors.mock_source.target import MockRagTarget
from packages.domain.models import Principal, RunOutcome
from packages.domain.scenario import ScenarioDefinition
from packages.test_engine.clock import SimulatedClock
from packages.test_engine.engine import PermissionRegressionEngine


def test_positive_control_timeout_is_a_precondition_failure():
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock)
    target = MockRagTarget(source=source, clock=clock, stale_acl_seconds=0)
    # A target that sees no marker proves that mutation must never begin.
    async def hidden_probe(*,principal,prompt):
        from packages.connector_sdk.target import TargetObservation
        return TargetObservation(available=True,answer="No matching information")
    target.probe=hidden_probe  # type: ignore[method-assign]
    scenario=ScenarioDefinition(name="positive_control_timeout",maximum_slo_seconds=2,timeout_seconds=10,positive_control={"timeout_seconds":2,"poll_interval_seconds":1,"required_observations":2})
    result=asyncio.run(PermissionRegressionEngine(source,target,clock=clock).run_revocation(allowed=Principal("alice"),denied_control=Principal("bob"),scenario=scenario))
    assert result.outcome is RunOutcome.PRECONDITION_FAILURE
    assert "AI_INGESTION_NOT_CONFIRMED" in result.reason
