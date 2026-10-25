"""Local-only synthetic Guard SQLite-cache benchmark. Not a production SLA."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter_ns
import statistics

from apps.guard.accessproof_guard.cache import PolicyCache


def pct(data, p):
    data = sorted(data)
    return data[min(len(data) - 1, round((len(data) - 1) * p))]


with TemporaryDirectory(prefix="ap-redteam-bench-") as td:
    policy = PolicyCache(str(Path(td) / "cache.db"))
    policy.install(1, [
        {"subject_id": "alice", "source_id": "drive", "resource_id": "visible",
         "decision": "allow"},
        {"subject_id": "bob", "source_id": "drive", "resource_id": "secret",
         "decision": "deny"},
    ])
    counts = {"allow": 0, "deny": 0}
    durations = []

    def attack(i):
        subject, doc, want = (
            ("alice", "visible", "allow") if i % 2 == 0
            else ("bob", "secret", "deny")
        )
        start = perf_counter_ns()
        decision, _ = policy.decide(subject, "drive", doc, "read")
        elapsed_ms = (perf_counter_ns() - start) / 1_000_000
        assert decision == want
        return want, elapsed_ms

    t0 = perf_counter_ns()
    with ThreadPoolExecutor(max_workers=8) as pool:
        for outcome, elapsed in pool.map(attack, range(2000)):
            counts[outcome] += 1
            durations.append(elapsed)
    total_s = (perf_counter_ns() - t0) / 1_000_000_000
    print("BENCHMARK=local SQLite PolicyCache, 8 threads, synthetic principals")
    print("DECISIONS=2000", "ALLOW="+str(counts["allow"]), "DENY="+str(counts["deny"]))
    print("P50_MS=%.4f P95_MS=%.4f P99_MS=%.4f MAX_MS=%.4f" % (
        statistics.median(durations), pct(durations, .95),
        pct(durations, .99), max(durations)
    ))
    print("THROUGHPUT_DECISIONS_PER_SEC=%.1f" % (2000 / total_s))
    assert counts == {"allow": 1000, "deny": 1000}
    print("SECURITY_OUTCOME=all 2000 synthetic decisions correct")
