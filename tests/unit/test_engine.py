import pytest
from packages.domain.models import Principal, RunOutcome
from packages.domain.scenario import PollingPolicy, ScenarioDefinition, StabilityPolicy
from packages.test_engine.clock import SimulatedClock
from packages.test_engine.engine import PermissionRegressionEngine
from connectors.mock_source.adapter import MockSourceAdapter
from connectors.mock_source.target import MockRagTarget


def scenario(slo=30, timeout=180):
    return ScenarioDefinition(
        name="direct_revoke",
        maximum_slo_seconds=slo,
        timeout_seconds=timeout,
        polling=PollingPolicy(
            initial_interval_seconds=10, maximum_interval_seconds=10, backoff_multiplier=1
        ),
        stability=StabilityPolicy(
            required_clean_observations=3, required_clean_duration_seconds=20
        ),
    )


@pytest.mark.asyncio
async def test_failing_propagation_slo():
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock)
    target = MockRagTarget(source=source, clock=clock, stale_acl_seconds=90)
    result = await PermissionRegressionEngine(source, target, clock=clock).run_revocation(
        allowed=Principal("alice"), denied_control=Principal("bob"), scenario=scenario()
    )
    assert result.outcome is RunOutcome.FAIL
    assert result.metrics.stable_propagation_latency_seconds == pytest.approx(110.0)
    assert result.metrics.last_observed_exposure_at is not None


@pytest.mark.asyncio
async def test_passing_propagation_slo():
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock)
    target = MockRagTarget(source=source, clock=clock, stale_acl_seconds=10)
    result = await PermissionRegressionEngine(source, target, clock=clock).run_revocation(
        allowed=Principal("alice"), denied_control=Principal("bob"), scenario=scenario(slo=40)
    )
    assert result.outcome is RunOutcome.PASS
    assert result.metrics.stable_propagation_latency_seconds == pytest.approx(30.0)


@pytest.mark.asyncio
async def test_target_outage_is_inconclusive():
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock)
    target = MockRagTarget(
        source=source, clock=clock, stale_acl_seconds=10, outage_after_revoke=True
    )
    result = await PermissionRegressionEngine(source, target, clock=clock).run_revocation(
        allowed=Principal("alice"), denied_control=Principal("bob"), scenario=scenario()
    )
    assert result.outcome is RunOutcome.INCONCLUSIVE


@pytest.mark.asyncio
async def test_positive_control_failure_is_not_pass():
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock)
    target = MockRagTarget(source=source, clock=clock, positive_never_ingests=True)
    result = await PermissionRegressionEngine(source, target, clock=clock).run_revocation(
        allowed=Principal("alice"), denied_control=Principal("bob"), scenario=scenario()
    )
    assert result.outcome is RunOutcome.PRECONDITION_FAILURE


@pytest.mark.asyncio
async def test_negative_control_leak_is_precondition_failure():
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock)
    target = MockRagTarget(source=source, clock=clock, force_negative_leak=True)
    result = await PermissionRegressionEngine(source, target, clock=clock).run_revocation(
        allowed=Principal("alice"), denied_control=Principal("bob"), scenario=scenario()
    )
    assert result.outcome is RunOutcome.PRECONDITION_FAILURE


@pytest.mark.asyncio
async def test_cancellation_does_not_pass():
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock)
    target = MockRagTarget(source=source, clock=clock, stale_acl_seconds=90)
    calls = {"n": 0}

    def cancel():
        calls["n"] += 1
        return calls["n"] >= 2

    result = await PermissionRegressionEngine(
        source, target, clock=clock, cancel_check=cancel
    ).run_revocation(
        allowed=Principal("alice"), denied_control=Principal("bob"), scenario=scenario()
    )
    assert result.outcome is RunOutcome.CANCELED


@pytest.mark.asyncio
async def test_provider_outage_after_mutation_is_inconclusive():
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock, provider_outage_after_mutation=True)
    target = MockRagTarget(source=source, clock=clock)
    result = await PermissionRegressionEngine(source, target, clock=clock).run_revocation(
        allowed=Principal("alice"), denied_control=Principal("bob"), scenario=scenario()
    )
    assert result.outcome is RunOutcome.INCONCLUSIVE
    assert "Provider unavailable" in result.reason


@pytest.mark.asyncio
async def test_cleanup_failure_is_recorded_without_changing_security_outcome():
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock, cleanup_failure=True)
    target = MockRagTarget(source=source, clock=clock, stale_acl_seconds=10)
    result = await PermissionRegressionEngine(source, target, clock=clock).run_revocation(
        allowed=Principal("alice"), denied_control=Principal("bob"), scenario=scenario(slo=40)
    )
    assert result.outcome is RunOutcome.PASS
    assert any("Cleanup pending" in event.detail for event in result.timeline)


@pytest.mark.asyncio
async def test_recovery_after_acknowledged_mutation_does_not_replay_destructive_call():
    from packages.test_engine.engine import EngineInterrupted

    class CountingSource(MockSourceAdapter):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.revoke_calls = 0

        async def revoke_access(self, resource, principal):
            self.revoke_calls += 1
            await super().revoke_access(resource, principal)

    clock = SimulatedClock()
    source = CountingSource(clock=clock)
    target = MockRagTarget(source=source, clock=clock, stale_acl_seconds=20)
    captured = {}

    async def checkpoint_hook(payload):
        captured.clear()
        captured.update(payload)
        if payload["phase"] == "mutation_acknowledged":
            raise EngineInterrupted("simulated runner crash after provider acknowledgement")

    first = PermissionRegressionEngine(
        source, target, clock=clock, checkpoint_callback=checkpoint_hook
    )
    with pytest.raises(EngineInterrupted):
        await first.run_revocation(
            allowed=Principal("alice"),
            denied_control=Principal("bob"),
            scenario=scenario(slo=50),
        )

    assert source.revoke_calls == 1
    assert captured["mutation_acknowledged"] is True
    assert captured["resource"]["provider_id"] in source.resources

    recovered = PermissionRegressionEngine(source, target, clock=clock)
    result = await recovered.run_revocation(
        allowed=Principal("alice"),
        denied_control=Principal("bob"),
        scenario=scenario(slo=50),
        resume_checkpoint=captured,
    )

    assert source.revoke_calls == 1
    assert result.outcome is RunOutcome.PASS
    assert result.metrics.source_ground_truth_changed_at is not None
    assert any("will not be replayed" in event.detail for event in result.timeline)


@pytest.mark.asyncio
async def test_recovery_re_adopts_checkpointed_resource_before_cleanup():
    from packages.connector_sdk.base import UnsafeBoundaryError
    from packages.test_engine.engine import EngineInterrupted

    class GuardedSource(MockSourceAdapter):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.owned = set()
            self.adopt_calls = 0

        async def create_resource(self, **kwargs):
            resource = await super().create_resource(**kwargs)
            self.owned.add(resource.provider_id)
            return resource

        async def adopt_tracked_resource(self, resource):
            if resource.marker != "accessproof-generated":
                raise UnsafeBoundaryError("invalid marker")
            self.adopt_calls += 1
            self.owned.add(resource.provider_id)

        async def delete_resource(self, resource):
            if resource.provider_id not in self.owned:
                raise UnsafeBoundaryError("resource ownership not rehydrated")
            await super().delete_resource(resource)
            self.owned.discard(resource.provider_id)

    clock = SimulatedClock()
    source = GuardedSource(clock=clock)
    target = MockRagTarget(source=source, clock=clock, stale_acl_seconds=10)
    captured = {}

    async def checkpoint_hook(payload):
        captured.clear()
        captured.update(payload)
        if payload["phase"] == "source_confirmed":
            raise EngineInterrupted("simulated crash after source confirmation")

    first = PermissionRegressionEngine(
        source, target, clock=clock, checkpoint_callback=checkpoint_hook
    )
    with pytest.raises(EngineInterrupted):
        await first.run_revocation(
            allowed=Principal("alice"), denied_control=Principal("bob"), scenario=scenario(slo=40)
        )

    assert captured["source_confirmed"] is True
    resource_id = captured["resource"]["provider_id"]
    source.owned.clear()  # simulate a fresh adapter instance losing its in-memory guard set

    recovered = PermissionRegressionEngine(source, target, clock=clock)
    result = await recovered.run_revocation(
        allowed=Principal("alice"),
        denied_control=Principal("bob"),
        scenario=scenario(slo=40),
        resume_checkpoint=captured,
    )

    assert source.adopt_calls == 1
    assert result.source_ground_truth_detail.principal == "alice"
    assert resource_id not in source.resources
    assert result.outcome is RunOutcome.PASS


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "group_member_remove",
        "share_link_revoke",
        "resource_delete",
        "parent_acl_change",
        "resource_move",
    ],
)
async def test_revocation_like_mutation_matrix_uses_real_adapter_paths(mutation):
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock)
    target = MockRagTarget(source=source, clock=clock, stale_acl_seconds=10)
    s = scenario(slo=40)
    s.mutation = mutation
    result = await PermissionRegressionEngine(source, target, clock=clock).run_revocation(
        allowed=Principal("alice"), denied_control=Principal("bob"), scenario=s
    )
    assert result.outcome is RunOutcome.PASS
    assert result.source_ground_truth == "DENIED"
    assert result.source_ground_truth_detail is not None
    assert result.source_ground_truth_detail.access_mechanism == mutation


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["direct_user_grant", "group_member_add"])
async def test_inverse_access_mutations_are_not_silently_executed_as_revokes(mutation):
    clock = SimulatedClock()
    source = MockSourceAdapter(clock=clock)
    target = MockRagTarget(source=source, clock=clock)
    s = scenario(slo=40)
    s.mutation = mutation
    result = await PermissionRegressionEngine(source, target, clock=clock).run_revocation(
        allowed=Principal("alice"), denied_control=Principal("bob"), scenario=s
    )
    assert result.outcome is RunOutcome.INCONCLUSIVE
    assert "not implemented" in result.reason


@pytest.mark.asyncio
async def test_failed_resource_delete_is_not_replayed_by_generic_cleanup():
    class AmbiguousDeleteSource(MockSourceAdapter):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.delete_calls = 0

        async def delete_resource(self, resource):
            self.delete_calls += 1
            raise RuntimeError("provider response lost after delete request")

    clock = SimulatedClock()
    source = AmbiguousDeleteSource(clock=clock)
    target = MockRagTarget(source=source, clock=clock)
    s = scenario(slo=40)
    s.mutation = "resource_delete"

    result = await PermissionRegressionEngine(source, target, clock=clock).run_revocation(
        allowed=Principal("alice"), denied_control=Principal("bob"), scenario=s
    )

    assert result.outcome is RunOutcome.ERROR
    assert source.delete_calls == 1
    assert any("Cleanup pending" in event.detail for event in result.timeline)
