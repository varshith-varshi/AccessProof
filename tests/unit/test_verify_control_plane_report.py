from datetime import datetime, timedelta, timezone

from packages.crypto.signing import Ed25519Signer
from scripts.verify_control_plane_report import REPORT_SCHEMA, verify_envelope


def _envelope(*, expires_at: datetime | None = None, organization_id="org-1"):
    now = datetime.now(timezone.utc)
    payload = {
        "schema": REPORT_SCHEMA,
        "report_id": "report-1",
        "report_type": "APPLICATION_COVERAGE",
        "organization_id": organization_id,
        "generated_at": now.isoformat(),
        "expires_at": (expires_at or now + timedelta(days=30)).isoformat(),
        "evidence_levels": {"guard_decisions": "NOT_OBSERVED"},
        "limitations": ["Metadata only."],
    }
    signature = Ed25519Signer.from_secret("unit-test-report-signing-key").sign(payload).as_dict()
    return {"report": payload, "signature": signature}


def _trust(envelope):
    signature = envelope["signature"]
    return {signature["key_id"]: signature["public_key"]}


def test_valid_envelope_verifies_only_with_pinned_issuer_key():
    envelope = _envelope()
    # Cryptographic validity without a caller-owned trust root is diagnostic
    # only and must never appear as a production-verified evidence export.
    assert verify_envelope(envelope)["verified"] is False
    result = verify_envelope(envelope, trusted_public_keys=_trust(envelope))
    assert result["verified"] is True
    assert result["checks"]["signature"] is True
    assert result["checks"]["not_expired"] is True


def test_tampered_payload_is_rejected():
    envelope = _envelope()
    envelope["report"]["organization_id"] = "org-2"
    result = verify_envelope(envelope, trusted_public_keys=_trust(envelope))
    assert result["verified"] is False
    assert result["checks"]["signature"] is False
    assert result["checks"]["organization"] is True


def test_expired_report_fails_unless_explicitly_allowed():
    envelope = _envelope(expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))
    assert verify_envelope(envelope, trusted_public_keys=_trust(envelope))["verified"] is False
    historical = verify_envelope(envelope, trusted_public_keys=_trust(envelope), allow_expired=True)
    assert historical["verified"] is True
    assert historical["checks"]["signature"] is True
    assert historical["checks"]["not_expired"] is True


def test_expected_scope_and_key_pin_are_enforced():
    envelope = _envelope(organization_id="org-1")
    trust = _trust(envelope)
    assert verify_envelope(envelope, trusted_public_keys=trust, expected_organization="org-1")["verified"] is True
    assert verify_envelope(envelope, trusted_public_keys=trust, expected_organization="org-2")["verified"] is False
    assert verify_envelope(
        envelope, trusted_public_keys=trust, expected_report_type="GUARD_HEALTH"
    )["verified"] is False
    key_id = envelope["signature"]["key_id"]
    assert verify_envelope(envelope, trusted_public_keys=trust, expected_key_id=key_id)["verified"] is True
    assert verify_envelope(envelope, trusted_public_keys=trust, expected_key_id="ed25519:other")["verified"] is False


def test_arbitrary_self_signed_or_revoked_issuer_is_not_production_trusted():
    envelope = _envelope()
    key_id = envelope["signature"]["key_id"]
    assert verify_envelope(envelope, trusted_public_keys={})["verified"] is False
    assert verify_envelope(envelope, trusted_public_keys=_trust(envelope), revoked_key_ids={key_id})["verified"] is False
    diagnostic = verify_envelope(envelope, allow_untrusted_self_signed=True)
    assert diagnostic["verified"] is True
    assert diagnostic["checks"]["trusted_issuer"] is True


def test_malformed_envelope_is_rejected():
    result = verify_envelope({"report": {}, "signature": {}})
    assert result["verified"] is False
    assert result["checks"]["schema"] is False
    assert result["checks"]["signature"] is False
    assert verify_envelope([])["verified"] is False
