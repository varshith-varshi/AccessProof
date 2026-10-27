"""Deterministic attacker-style Guard policy state-machine regression.

Sixteen independent seeds stress late grants/denials, duplicate source revisions
and intentionally reordered provider events in the isolated SQLite Guard cache.
The oracle does NOT call AccessProof to compute its expected decisions.
"""
from __future__ import annotations

import random

import pytest

from apps.guard.accessproof_guard.cache import PolicyCache


RANK = {"allow": 0, "unknown": 1, "deny": 2}


@pytest.mark.parametrize("seed", range(16))
def test_sequenced_envelopes_never_resurrect_stale_permissions(seed: int, tmp_path):
    randomizer = random.Random(seed + 20261022)
    cache = PolicyCache(str(tmp_path / f"policy-replay-{seed}.db"))
    keys = [(f"employee-{user}", f"doc-{resource}")
            for user in range(4) for resource in range(8)]
    expected: dict[tuple[str, str], tuple[int, str]] = {}

    for envelope in range(1, 121):
        employee, resource = randomizer.choice(keys)
        # Some newest envelopes contain delayed source events. This is common
        # when provider deltas arrive out of order or jobs retry old batches.
        revision = randomizer.randint(max(1, envelope - 20), envelope)
        decision = randomizer.choice(["allow", "deny", "unknown"])
        current = expected.get((employee, resource))
        if (
            current is None
            or revision > current[0]
            or (revision == current[0] and RANK[decision] > RANK[current[1]])
        ):
            expected[(employee, resource)] = (revision, decision)

        assert cache.install(envelope, [{
            "subject_id": employee,
            "source_id": "simulated-provider-source",
            "resource_id": resource,
            "scope": "read",
            "decision": decision,
            "version": revision,
            "reason": f"SYNTHETIC_REVISION_{revision}",
        }])

        for person, document in keys:
            stored, _ = cache.decide(
                person, "simulated-provider-source", document, "read",
            )
            trusted_state = expected.get((person, document))
            expected_decision = trusted_state[1] if trusted_state else "unknown"
            assert stored == expected_decision, (
                f"seed={seed}, envelope={envelope}, "
                f"subject={person}, resource={document}"
            )
