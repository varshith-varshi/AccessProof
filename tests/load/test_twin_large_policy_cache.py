"""Two-tenant 10k-document synthetic customer fixture against the real Guard cache."""
from __future__ import annotations

import json
import random
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from apps.guard.accessproof_guard.cache import PolicyCache


FIXTURE = Path(__file__).resolve().parents[2] / "customer_simulation/fixtures/performance-metadata.json"


def test_large_customer_10000_documents_tenant_isolation_and_revocation(tmp_path):
    docs = json.loads(FIXTURE.read_text())
    assert len(docs) == 10_000
    assert len({(d["tenant"], d["source_id"], d["resource_id"]) for d in docs}) == 10_000

    cache = PolicyCache(str(tmp_path / "enterprise-guard.db"))
    rows = [
        {
            "subject_id": "shared-name-alice",
            "source_id": doc["source_id"],
            "resource_id": doc["resource_id"],
            "scope": "read",
            "decision": "allow" if doc["source_id"] == "northstar-drive" else "deny",
            "reason": "SYNTHETIC_LOAD",
        }
        for doc in docs
    ]
    assert cache.install(1, rows)
    assert cache.version() == 1

    # Identical subject and resource IDs across companies must be isolated.
    for doc in docs:
        decision, _ = cache.decide(
            "shared-name-alice", doc["source_id"], doc["resource_id"], "read"
        )
        assert decision == ("allow" if doc["source_id"] == "northstar-drive" else "deny")

    # For each resource the same string ID exists at both companies. A
    # successful grant on one source must not make the other source readable.
    sample = docs[123]
    other = ("blueharbor-drive" if sample["source_id"] == "northstar-drive"
             else "northstar-drive")
    assert cache.decide("shared-name-alice", other, sample["resource_id"], "read")[0] != (
        cache.decide("shared-name-alice", sample["source_id"], sample["resource_id"], "read")[0]
    )

    # 2,000 new denial policies simulate a bulk employee offboarding.
    batch = [
        {
            "subject_id": "shared-name-alice", "source_id": doc["source_id"],
            "resource_id": doc["resource_id"], "scope": "read",
            "decision": "deny", "reason": "OFFBOARDED",
        }
        for doc in docs if doc["source_id"] == "northstar-drive"
    ][:2000]
    assert cache.install(2, batch)
    for entry in batch:
        assert cache.decide(
            entry["subject_id"], entry["source_id"], entry["resource_id"], "read"
        )[0] == "deny"

    # Concurrently query at least 24,000 mixed allow/deny/unknown decisions.
    def check(worker_id: int):
        randomizer = random.Random(worker_id + 20261021)
        for _ in range(3000):
            doc = docs[randomizer.randrange(len(docs))]
            decision, _ = cache.decide(
                "shared-name-alice", doc["source_id"], doc["resource_id"], "read"
            )
            assert decision in {"allow", "deny"}
            assert cache.decide("missing-employee", doc["source_id"], doc["resource_id"], "read")[0] == "unknown"
        return 3000

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(check, range(8))) == 24_000
