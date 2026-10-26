"""Unsafe mutable OIDC subject claim configurations: synthetic identities only."""
from __future__ import annotations

import httpx
import pytest

from apps.guard.accessproof_guard.identity import IdentityError, OidcVerifier
from apps.guard.accessproof_guard.onboarding import EnrollmentError, enroll_guard


@pytest.mark.parametrize("claim", ["email", "preferred_username", "name", "role"])
def test_oidc_verifier_rejects_mutable_identity_key_before_verification(claim: str) -> None:
    """Reassigned emails/display names must never inherit the previous user's ACL."""
    with pytest.raises(IdentityError, match="IDENTITY_SUBJECT_CLAIM_UNSAFE"):
        OidcVerifier(
            issuer="https://synthetic-issuer.test", audience="rag",
            subject_claim=claim,
            client=httpx.Client(transport=httpx.MockTransport(
                lambda _: pytest.fail("An unsafe identity must never fetch JWKS"),
            )),
        )


@pytest.mark.parametrize("claim", ["email", "preferred_username"])
def test_guard_enrollment_rejects_mutable_identity_before_exchanging_token(
    tmp_path, claim: str,
) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        pytest.fail("Unsafe enrollment must never consume its one-time token")

    with pytest.raises(EnrollmentError, match="Stable subject claim"):
        enroll_guard(
            server="https://control.synthetic.test",
            token="SYNTHETIC_ONLY",
            version="test", state_dir=tmp_path, issuer="https://id.synthetic.test",
            audience="rag", subject_claim=claim,
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )


def test_guard_enrollment_supports_immutable_oid_claim_and_keeps_credentials_private(
    tmp_path,
) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "guard_id": "synthetic-guard-id",
            "guard_credential": "SYNTHETIC_TEST_CREDENTIAL",
        })

    state = enroll_guard(
        server="https://control.synthetic.test", token="SYNTHETIC_ONLY",
        version="test", state_dir=tmp_path, issuer="https://id.synthetic.test",
        audience="rag", subject_claim="oid",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert state["subject_claim"] == "oid"
    assert state["guard_id"] == "synthetic-guard-id"
    assert (tmp_path / "credentials.json").exists()
