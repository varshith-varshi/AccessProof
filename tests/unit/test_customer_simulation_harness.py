"""Integrity tests for the local-only customer simulation assets."""
from __future__ import annotations

import csv
import json

from customer_simulation.harness.digital_twin import ROOT, generate_corpus, write_artifacts


def test_customer_twin_generates_realistic_synthetic_corpus_and_matrix() -> None:
    summary = write_artifacts()
    corpus = generate_corpus(250)
    assert summary == {"smoke_documents": 250, "performance_metadata": 10_000, "scenarios": 150, "locally_executed_end_to_end": 0, "external_sandbox_required": 26}
    assert {item.tenant for item in corpus} == {"northstar.example", "blueharbor.example"}
    # Same provider IDs intentionally collide across tenants; the source ID
    # remains part of every key used by the real Guard/SDK contract.
    collisions = [item for item in corpus if item.resource_id == "file-0000"]
    assert len(collisions) == 2 and len({item.source_id for item in collisions}) == 2
    assert any(item.canary and item.classification == "finance" for item in corpus)
    with (ROOT / "02_scenario_matrix.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 150
    assert len({row["ID"] for row in rows}) == 150
    assert {row["execution_status"] for row in rows} == {
        "NOT_EXECUTED_INDIVIDUALLY", "EXTERNAL_SANDBOX_REQUIRED",
    }
    assert all(row["result"] == "NOT_TESTED" for row in rows)
    assert len({row["customer_story"] for row in rows}) == 150
    for key in ("identity", "resource", "provider", "rag", "policy"):
        assert len({
            part for row in rows for part in row["customer_story"].split("; ")
            if part.startswith(key + "=")
        }) >= 5
    evidence = json.loads((ROOT / "evidence" / "latest-summary.json").read_text(encoding="utf-8"))
    assert evidence == summary
