"""D-16: one precedence rule for Guard employee-identity settings."""
from apps.guard.accessproof_guard.app import _resolve_identity_settings

SAVED = {
    "issuer": "https://login.microsoftonline.com/t/v2.0", "audience": "enrolled-aud",
    "subject_claim": "sub", "identity_mode": "oidc", "tenant_id": "",
}


def test_explicit_environment_wins_for_every_identity_setting():
    env = {
        "ACCESSPROOF_GUARD_JWT_ISSUER": "https://login.microsoftonline.com/t2/v2.0",
        "ACCESSPROOF_GUARD_JWT_AUDIENCE": "rag-app",
        "ACCESSPROOF_GUARD_IDENTITY_TENANT_ID": "t2",
        "ACCESSPROOF_GUARD_IDENTITY_SUBJECT_CLAIM": "oid",
        "ACCESSPROOF_GUARD_IDENTITY_MODE": "OIDC",
    }
    r = _resolve_identity_settings(env, SAVED)
    assert r == {"issuer": env["ACCESSPROOF_GUARD_JWT_ISSUER"], "audience": "rag-app",
                 "tenant_id": "t2", "subject_claim": "oid", "identity_mode": "oidc"}


def test_enrollment_record_used_when_environment_unset():
    r = _resolve_identity_settings({}, SAVED)
    assert (r["issuer"], r["audience"], r["subject_claim"], r["identity_mode"]) == (
        SAVED["issuer"], "enrolled-aud", "sub", "oidc")
    assert r["tenant_id"] is None  # empty string is "not set", never a pinned tenant


def test_defaults_without_any_configuration():
    assert _resolve_identity_settings({}, {})["subject_claim"] == "sub"
    assert _resolve_identity_settings({}, {})["identity_mode"] == "oidc"
    assert _resolve_identity_settings({"ACCESSPROOF_GUARD_JWT_VERIFICATION_KEY": "k"}, {})["identity_mode"] == "static"


def test_empty_environment_value_does_not_clear_enrolled_value():
    r = _resolve_identity_settings({"ACCESSPROOF_GUARD_IDENTITY_SUBJECT_CLAIM": "", "ACCESSPROOF_GUARD_JWT_AUDIENCE": ""}, SAVED)
    assert r["subject_claim"] == "sub" and r["audience"] == "enrolled-aud"
