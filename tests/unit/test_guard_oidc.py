from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from apps.guard.accessproof_guard.identity import IdentityError, OidcVerifier


ISSUER = "https://issuer.example.test"
AUDIENCE = "api://rag"


def _jwk(private_key: rsa.RSAPrivateKey, kid: str) -> dict[str, object]:
    payload = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    payload.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return payload


def _token(private_key: rsa.RSAPrivateKey, kid: str, **overrides: object) -> str:
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "google-stable-subject",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})


def _verifier(handler, **kwargs: object) -> OidcVerifier:
    return OidcVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        subject_claim=str(kwargs.pop("subject_claim", "sub")),
        tenant_id=kwargs.pop("tenant_id", None),
        cache_seconds=300,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_oidc_verifier_discovers_caches_and_accepts_rotated_key(monkeypatch) -> None:
    first, second = rsa.generate_private_key(public_exponent=65537, key_size=2048), rsa.generate_private_key(public_exponent=65537, key_size=2048)
    calls: list[str] = []
    keys = [_jwk(first, "one")]

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": f"{ISSUER}/keys"})
        return httpx.Response(200, json={"keys": keys})

    verifier = _verifier(handler)
    assert verifier.verify(_token(first, "one")).subject == "google-stable-subject"
    keys[:] = [_jwk(second, "two")]
    # Within the refresh floor an unknown kid cannot force a refetch
    # (attacker-controlled kids must not amplify into IdP traffic).
    with pytest.raises(IdentityError, match="IDENTITY_TOKEN_INVALID"):
        verifier.verify(_token(second, "two"))
    assert calls.count("/keys") == 1
    import time as _time
    later = _time.monotonic() + verifier.min_refresh_seconds + 1
    monkeypatch.setattr(_time, "monotonic", lambda: later)
    assert verifier.verify(_token(second, "two")).subject == "google-stable-subject"
    # Discovery is cached; after the floor an unknown kid causes one bounded JWKS refresh.
    assert calls.count("/.well-known/openid-configuration") == 1
    assert calls.count("/keys") == 2


@pytest.mark.parametrize(
    ("claims", "tenant", "code"),
    [
        ({"exp": datetime.now(timezone.utc) - timedelta(minutes=1)}, None, "IDENTITY_TOKEN_EXPIRED"),
        ({"iss": "https://wrong.example.test"}, None, "IDENTITY_ISSUER_MISMATCH"),
        ({"aud": "wrong-audience"}, None, "IDENTITY_AUDIENCE_MISMATCH"),
        ({"tid": "wrong"}, "expected", "IDENTITY_TENANT_MISMATCH"),
        ({"sub": ""}, None, "IDENTITY_SUBJECT_UNKNOWN"),
    ],
)
def test_oidc_verifier_returns_safe_claim_failure_codes(claims, tenant, code) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": f"{ISSUER}/keys"})
        return httpx.Response(200, json={"keys": [_jwk(key, "one")]})

    with pytest.raises(IdentityError, match=code):
        _verifier(handler, tenant_id=tenant).verify(_token(key, "one", **claims))


def test_oidc_verifier_rejects_none_algorithm_without_fetching_keys() -> None:
    verifier = _verifier(lambda _: pytest.fail("JWKS must not be fetched"))
    token = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "subject"}, key="", algorithm="none")
    with pytest.raises(IdentityError, match="IDENTITY_TOKEN_INVALID"):
        verifier.verify(token)


def test_oidc_verifier_preserves_trailing_slash_issuer_exactly() -> None:
    issuer = "https://tenant.example.test/"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json={"issuer": issuer, "jwks_uri": "https://tenant.example.test/keys"})
        return httpx.Response(200, json={"keys": [_jwk(key, "one")]})

    verifier = OidcVerifier(issuer=issuer, audience=AUDIENCE, subject_claim="sub", client=httpx.Client(transport=httpx.MockTransport(handler)))
    token = jwt.encode({"iss": issuer, "aud": AUDIENCE, "sub": "employee-1", "iat": datetime.now(timezone.utc), "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}, key, algorithm="RS256", headers={"kid": "one"})
    assert verifier.verify(token).issuer == issuer

    def altered_discovery(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"issuer": issuer.rstrip("/"), "jwks_uri": "https://tenant.example.test/keys"})
    with pytest.raises(IdentityError, match="IDENTITY_ISSUER_MISMATCH"):
        OidcVerifier(issuer=issuer, audience=AUDIENCE, subject_claim="sub", client=httpx.Client(transport=httpx.MockTransport(altered_discovery))).verify(token)


def test_adversarial_jwks_cannot_redirect_guard_to_loopback() -> None:
    """An issuer-controlled JWKS URL cannot turn the Guard into an SSRF proxy."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    called: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append(str(request.url))
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json={
                "issuer": ISSUER, "jwks_uri": "https://127.0.0.1:8443/steal-local-data",
            })
        return httpx.Response(200, json={"keys": [_jwk(key, "one")]})

    with pytest.raises(IdentityError, match="IDENTITY_KEY_UNAVAILABLE"):
        _verifier(handler).verify(_token(key, "one"))
    assert len(called) == 1, called


@pytest.mark.parametrize("issuer", [
    "https://127.0.0.1", "https://169.254.169.254",
    "https://localhost", "https://metadata.internal",
])
def test_adversarial_oidc_issuer_cannot_be_private(issuer: str) -> None:
    with pytest.raises(IdentityError, match="IDENTITY_ISSUER_INVALID"):
        OidcVerifier(
            issuer=issuer, audience=AUDIENCE, subject_claim="sub",
            client=httpx.Client(transport=httpx.MockTransport(
                lambda _: pytest.fail("private issuer must not be fetched")
            )),
        )
