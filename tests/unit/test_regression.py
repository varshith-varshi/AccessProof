from packages.test_engine.regression import (
    ReleaseDecision,
    ScenarioMeasurement,
    compare_measurements,
    decide_release,
)


def m(release, outcome, latency, *, severity="REQUIRED", caps=("DIRECT_USER_REVOKE",)):
    return ScenarioMeasurement("suite-1", "Group revoke", severity, release, outcome, latency, caps)


def test_historical_latency_regression_blocks_required_scenario():
    regression = compare_measurements(
        m("4.7", "PASS", 40), m("4.8", "PASS", 200), maximum_absolute_regression_seconds=30
    )
    assert regression.absolute_regression_seconds == 160
    assert regression.regression_exceeded is True
    assert regression.blocking is True
    assert decide_release([regression]) is ReleaseDecision.FAIL


def test_optional_regression_does_not_block_release():
    regression = compare_measurements(
        m("4.7", "PASS", 40, severity="OPTIONAL"),
        m("4.8", "PASS", 200, severity="OPTIONAL"),
        maximum_absolute_regression_seconds=30,
    )
    assert regression.regression_exceeded is True
    assert regression.blocking is False
    assert decide_release([regression]) is ReleaseDecision.PASS


def test_capability_loss_is_detected():
    baseline = m("4.7", "PASS", 40, caps=("DIRECT_USER_REVOKE", "GROUP_MEMBER_REMOVE"))
    candidate = m("4.8", "PASS", 42, caps=("DIRECT_USER_REVOKE",))
    regression = compare_measurements(baseline, candidate, maximum_absolute_regression_seconds=30)
    assert regression.capability_loss == ("GROUP_MEMBER_REMOVE",)
    assert regression.blocking is True


def test_error_and_cancellation_block_even_when_inconclusive_is_optional():
    for outcome in ("ERROR", "CANCELED"):
        regression = compare_measurements(
            m("old", "PASS", 1), m("new", outcome, None), block_on_inconclusive=False
        )
        assert decide_release([regression], block_on_inconclusive=False) is ReleaseDecision.FAIL


def test_empty_release_is_not_a_pass():
    assert decide_release([]) is ReleaseDecision.INCONCLUSIVE
