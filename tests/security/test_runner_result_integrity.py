"""Runner result integrity: server-issued oracle and PASS evidence gates."""
from __future__ import annotations

from apps.api.accessproof_api.app import _require_valid_pass_evidence
from apps.api.accessproof_api.db import TestRun as DbTestRun, TestSuite as DbTestSuite
from fastapi import HTTPException
from packages.domain.scenario import ScenarioDefinition


def _suite() -> DbTestSuite:
    scenario = ScenarioDefinition(name="required-revoke", maximum_slo_seconds=60, timeout_seconds=120)
    return DbTestSuite(id="suite", scenario_json=scenario.model_dump_json())


def _run() -> DbTestRun:
    return DbTestRun(id="run", oracle_canary="AP-CANARY-server-bound")


def _result() -> dict:
    return {
        "run_id": "run", "outcome": "PASS", "source_ground_truth": "DENIED",
        "expected_slo_seconds": 60, "derived": {"stable_propagation_latency_seconds": 3},
        "observations": [{"exposed": False, "response_hash": "a" * 64}] * 3,
        "timeline": [{"state": state} for state in ("VERIFYING_SOURCE_GROUND_TRUTH", "VERIFYING_STABLE_DENIAL", "PASSED")],
    }


def _checkpoint(canary="AP-CANARY-server-bound") -> dict:
    return {"source_confirmed": True, "resource": {"canary": canary}}


def test_pass_with_zero_evidence_is_rejected():
    result = _result()
    result["observations"] = []
    try:
        _require_valid_pass_evidence(_run(), _suite(), result, _checkpoint())
    except HTTPException as exc:
        assert exc.status_code == 422
    else:
        raise AssertionError("empty PASS evidence was accepted")


def test_pass_with_substituted_checkpoint_canary_is_rejected():
    try:
        _require_valid_pass_evidence(_run(), _suite(), _result(), _checkpoint("AP-CANARY-attacker"))
    except HTTPException as exc:
        assert exc.status_code == 422
    else:
        raise AssertionError("foreign checkpoint canary was accepted")
