from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class BaselinePolicy(str, Enum):
    PREVIOUS_SUCCESSFUL = "previous_successful"
    PINNED = "pinned"
    MANUAL = "manual"


class ReleaseDecision(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True, slots=True)
class ScenarioMeasurement:
    suite_id: str
    suite_name: str
    severity: str
    release: str
    outcome: str
    stable_latency_seconds: float | None
    source_capabilities: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScenarioRegression:
    suite_id: str
    suite_name: str
    severity: str
    baseline_release: str | None
    candidate_release: str
    baseline_outcome: str | None
    candidate_outcome: str
    baseline_latency_seconds: float | None
    candidate_latency_seconds: float | None
    absolute_regression_seconds: float | None
    percentage_regression: float | None
    newly_failing: bool
    newly_inconclusive: bool
    capability_loss: tuple[str, ...]
    regression_exceeded: bool
    blocking: bool


def compare_measurements(
    baseline: ScenarioMeasurement | None,
    candidate: ScenarioMeasurement,
    *,
    maximum_absolute_regression_seconds: float | None = 30.0,
    maximum_percentage_regression: float | None = None,
    block_on_inconclusive: bool = True,
) -> ScenarioRegression:
    b_latency = baseline.stable_latency_seconds if baseline else None
    c_latency = candidate.stable_latency_seconds
    delta = None if b_latency is None or c_latency is None else c_latency - b_latency
    pct = None
    if delta is not None and b_latency is not None and b_latency != 0:
        pct = (delta / b_latency) * 100.0
    regression_exceeded = False
    if delta is not None and maximum_absolute_regression_seconds is not None:
        regression_exceeded = delta > maximum_absolute_regression_seconds
    if pct is not None and maximum_percentage_regression is not None:
        regression_exceeded = regression_exceeded or pct > maximum_percentage_regression

    baseline_outcome = baseline.outcome if baseline else None
    newly_failing = candidate.outcome == "FAIL" and baseline_outcome != "FAIL"
    newly_inconclusive = candidate.outcome in {
        "INCONCLUSIVE",
        "PRECONDITION_FAILURE",
    } and baseline_outcome not in {"INCONCLUSIVE", "PRECONDITION_FAILURE"}
    baseline_caps = set(baseline.source_capabilities if baseline else ())
    candidate_caps = set(candidate.source_capabilities)
    capability_loss = tuple(sorted(baseline_caps - candidate_caps))

    required = candidate.severity == "REQUIRED"
    outcome_blocks = candidate.outcome in {"FAIL", "ERROR", "CANCELED"} or (
        block_on_inconclusive
        and candidate.outcome in {"INCONCLUSIVE", "PRECONDITION_FAILURE", "ERROR"}
    )
    blocking = required and (outcome_blocks or regression_exceeded or bool(capability_loss))
    return ScenarioRegression(
        suite_id=candidate.suite_id,
        suite_name=candidate.suite_name,
        severity=candidate.severity,
        baseline_release=baseline.release if baseline else None,
        candidate_release=candidate.release,
        baseline_outcome=baseline_outcome,
        candidate_outcome=candidate.outcome,
        baseline_latency_seconds=b_latency,
        candidate_latency_seconds=c_latency,
        absolute_regression_seconds=delta,
        percentage_regression=pct,
        newly_failing=newly_failing,
        newly_inconclusive=newly_inconclusive,
        capability_loss=capability_loss,
        regression_exceeded=regression_exceeded,
        blocking=blocking,
    )


def decide_release(
    regressions: list[ScenarioRegression], *, block_on_inconclusive: bool = True
) -> ReleaseDecision:
    if not regressions:
        return ReleaseDecision.INCONCLUSIVE
    if any(item.blocking for item in regressions):
        return ReleaseDecision.FAIL
    required = [item for item in regressions if item.severity == "REQUIRED"]
    if block_on_inconclusive and any(
        item.candidate_outcome in {"INCONCLUSIVE", "PRECONDITION_FAILURE", "ERROR"}
        for item in required
    ):
        return ReleaseDecision.INCONCLUSIVE
    return ReleaseDecision.PASS
