from apps.api.accessproof_api.protection_state import (
    PROTECTION_STATES,
    STATE_MESSAGES,
    classify_protection_state,
    classify_shadow,
)


def _classify(checks=(), mode="protect", **overrides):
    values = {
        "adapter_protect_capable": True,
        "has_guard": True,
        "has_source": True,
        "guard_revoked": False,
        "source_disconnected": False,
        "certification_expired": False,
    }
    values.update(overrides)
    return classify_protection_state(
        list(checks), mode, **values
    )


def _failed(*codes):
    return [{"code": code, "ok": False} for code in codes]


def test_every_state_has_a_user_facing_message():
    assert set(PROTECTION_STATES) == set(STATE_MESSAGES)


def test_unsupported_adapter_never_reports_protected():
    assert _classify(mode="protect", adapter_protect_capable=False) == "UNSUPPORTED"


def test_missing_guard_or_source_is_not_configured_not_protected():
    assert _classify(mode="protect", has_guard=False) == "NOT_CONFIGURED"
    assert _classify(mode="protect", has_source=False) == "NOT_CONFIGURED"


def test_revoked_guard_or_disconnected_source_is_blocked():
    assert _classify(mode="protect", guard_revoked=True) == "BLOCKED"
    assert _classify(mode="protect", source_disconnected=True) == "BLOCKED"


def test_protect_with_all_checks_passing_is_verified():
    assert _classify(mode="protect") == "PROTECTED_VERIFIED"


def test_protect_with_unknown_check_failure_is_not_promoted():
    assert _classify(_failed("SOMETHING_NEW"), mode="protect") == "DEGRADED"


def test_protect_with_only_stale_evidence_is_stale():
    assert _classify(
        _failed("GUARD_HEARTBEAT_RECENT", "PERMISSION_SOURCE_SYNCED"), mode="protect"
    ) == "STALE"


def test_protect_with_only_certification_failures_is_validating_or_expired():
    assert _classify(
        _failed("LAYER1_INTEGRATION_CONFIRMED"), mode="protect"
    ) == "VALIDATING"
    assert _classify(
        _failed("LAYER1_INTEGRATION_CONFIRMED"),
        mode="protect",
        certification_expired=True,
    ) == "CERTIFICATION_EXPIRED"


def test_protect_pending_is_not_verified_even_with_no_failed_checks():
    assert _classify(mode="protect_pending") == "PROTECT_PENDING"


def test_shadow_is_never_protected():
    assert _classify(mode="shadow") == "SHADOW"
    assert _classify(_failed("LAYER1_INTEGRATION_CONFIRMED"), mode="shadow") == "SHADOW"
    assert _classify(_failed("SOMETHING_NEW"), mode="shadow") == "CONNECTED"


def test_unknown_mode_is_unknown():
    assert _classify(mode="enforce") == "UNKNOWN"


def test_shadow_stale_configuration_is_not_reported_as_connected():
    assert classify_shadow({"GUARD_HEARTBEAT_RECENT"}) == "STALE"
