"""A paired Gateway automatically reports server preflight; never Protect."""
from apps.gateway.accessproof_gateway.customer_connect import summarize_automatic_verification


def _claim(**kwargs):
    report = {
        "state": "action_required",
        "checks_passed": 12,
        "checks_total": 21,
        "failed_check_codes": [
            "MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED",
            "CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED",
        ],
        "production_certification": False,
        "protect_activated": False,
    }
    report.update(kwargs)
    return {"verification": report}


def test_post_pairing_verification_displays_all_actionable_blocks():
    lines = summarize_automatic_verification(_claim())
    assert "12/21" in lines[0]
    assert any("MICROSOFT_EFFECTIVE_PERMISSIONS_NOT_CERTIFIED" in x for x in lines)
    assert any("CUSTOMER_RAG_CHALLENGE_AGENT_REQUIRED" in x for x in lines)
    assert any("NOT certified or active" in x for x in lines)


def test_missing_server_snapshot_fails_closed():
    lines = summarize_automatic_verification({})
    assert "unavailable" in lines[0]
    assert "NOT certified" in lines[1]


def test_fake_success_claim_does_not_activate_protect():
    for problem in (
        {"production_certification": True},
        {"protect_activated": True},
        {"state": "protected"},
        {"checks_passed": 10000},
        {"failed_check_codes": ["INJECTED\nFAKE_SUCCESS"]},
        {"failed_check_codes": "MALFORMED"},
    ):
        lines = summarize_automatic_verification(_claim(**problem))
        assert "INVALID or unavailable" in lines[0]
        assert "NOT certified" in lines[1]


def test_all_green_preflight_keeps_independent_certification_required():
    lines = summarize_automatic_verification(_claim(
        state="checks_passed_requires_independent_review",
        checks_passed=21,
        failed_check_codes=[],
    ))
    assert "21/21" in lines[0]
    assert "NOT certified" in lines[-1]
