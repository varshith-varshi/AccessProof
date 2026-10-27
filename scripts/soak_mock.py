from __future__ import annotations

import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from connectors.mock_source.adapter import MockSourceAdapter
from connectors.mock_source.target import MockRagTarget
from packages.domain.models import Principal, RunOutcome
from packages.domain.scenario import PollingPolicy, ScenarioDefinition, StabilityPolicy
from packages.test_engine.clock import SimulatedClock
from packages.test_engine.engine import PermissionRegressionEngine

MUTATIONS = [
    "direct_user_revoke",
    "group_member_remove",
    "share_link_revoke",
    "resource_delete",
    "parent_acl_change",
    "resource_move",
]


class CountingSource(MockSourceAdapter):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.mutations = Counter()

    async def revoke_access(self, resource, principal):
        self.mutations["direct_user_revoke"] += 1
        return await super().revoke_access(resource, principal)

    async def remove_group_member(self, group_id, principal):
        self.mutations["group_member_remove"] += 1
        return await super().remove_group_member(group_id, principal)

    async def revoke_share_link(self, resource, link_id):
        self.mutations["share_link_revoke"] += 1
        return await super().revoke_share_link(resource, link_id)

    async def delete_resource(self, resource):
        if resource.metadata.get("delete_requested_by_scenario"):
            self.mutations["resource_delete"] += 1
        return await super().delete_resource(resource)

    async def revoke_parent_access(self, resource, principal):
        self.mutations["parent_acl_change"] += 1
        return await super().revoke_parent_access(resource, principal)

    async def move_resource(self, resource):
        self.mutations["resource_move"] += 1
        return await super().move_resource(resource)


async def one_run(index: int) -> tuple[str, str]:
    mutation = MUTATIONS[index % len(MUTATIONS)]
    clock = SimulatedClock()
    source_delay = [0, 2, 5][index % 3]
    stale = [5, 20, 60, 90][index % 4]
    source = CountingSource(clock=clock, source_mutation_delay_seconds=source_delay)
    target = MockRagTarget(source=source, clock=clock, stale_acl_seconds=stale)
    scenario = ScenarioDefinition(
        name=f"soak_{mutation}",
        mutation=mutation,
        maximum_slo_seconds=40,
        timeout_seconds=180,
        polling=PollingPolicy(
            initial_interval_seconds=5,
            maximum_interval_seconds=10,
            backoff_multiplier=1.5,
            maximum_probes=100,
        ),
        stability=StabilityPolicy(
            required_clean_observations=3, required_clean_duration_seconds=10
        ),
    )
    result = await PermissionRegressionEngine(source, target, clock=clock).run_revocation(
        allowed=Principal("alice", email="alice@example.invalid"),
        denied_control=Principal("bob", email="bob@example.invalid"),
        scenario=scenario,
    )
    if result.outcome not in {RunOutcome.PASS, RunOutcome.FAIL}:
        raise AssertionError(
            f"run {index} {mutation}: unexpected {result.outcome.value}: {result.reason}"
        )
    if source.mutations[mutation] != 1:
        raise AssertionError(f"run {index} {mutation}: mutation count={source.mutations[mutation]}")
    if source.resources:
        raise AssertionError(f"run {index} {mutation}: resource leak {list(source.resources)}")
    if source.groups:
        raise AssertionError(f"run {index} {mutation}: helper-group leak {list(source.groups)}")
    return mutation, result.outcome.value


async def main() -> None:
    summary = Counter()
    by_mutation = Counter()
    for i in range(120):
        mutation, outcome = await one_run(i)
        summary[outcome] += 1
        by_mutation[mutation] += 1
    print(
        json.dumps(
            {
                "runs": sum(summary.values()),
                "outcomes": dict(summary),
                "mutation_runs": dict(by_mutation),
                "resource_leaks": 0,
                "helper_artifact_leaks": 0,
                "duplicate_mutations": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
