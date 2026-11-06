"""Source-specific validation reports are diagnostic only, never Protect approval."""
from scripts.sharepoint_validation_readiness import summarize_checks

MANDATORY_CODES = [
    "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED",
    "V1_PROVIDER_SCOPE",
    "PRODUCTION_OIDC_READY",
    "PERMISSION_SOURCE_USABLE",
    "GATEWAY_LIVE_AND_ENFORCEMENT_READY",
    "HUMAN_ACTIVATION_APPROVAL_REQUIRED",
]


def example_rows() -> list[dict]:
    return [{"code": code, "ok": True} for code in MANDATORY_CODES]


def test_empty_checklist_rejects_protect():
    result = summarize_checks([])
    assert result["readiness"] == "NO_GO"
    assert not result["certificate_verified"]


def test_sharepoint_missing_certificate_rejects_release():
    checks = example_rows()
    checks[0]["ok"] = False
    result = summarize_checks(checks)
    assert result["readiness"] == "NO_GO"
    assert "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED" in result["failed_checks"]
    assert result["safe_to_enable_protect"] is False


def test_incomplete_checklist_is_rejected_even_if_all_present_are_green():
    result = summarize_checks([{"code": "V1_PROVIDER_SCOPE", "ok": True}])
    assert result["readiness"] == "NO_GO"
    assert "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED" in result["failed_checks"]


def test_malformed_and_duplicate_codes_fail_closed():
    for checks in (
        [{"code": "V1_PROVIDER_SCOPE", "ok": 1}],
        [{"code": "V1_PROVIDER_SCOPE", "ok": True}] * 2,
        [{"code": "", "ok": True}],
        [None],
    ):
        result = summarize_checks(checks)
        assert result["readiness"] == "NO_GO"
        assert result["failed_checks"] == ["CHECKLIST_INVALID"]


def test_all_checks_green_never_activate_protect():
    result = summarize_checks(example_rows())
    assert result["readiness"] == "CHECKS_PASSED_REQUIRES_INDEPENDENT_REVIEW"
    assert result["certificate_verified"] is True
    assert result["safe_to_enable_protect"] is False
