"""Entra employee-token negative matrix against the Guard verifier (synthetic keys).

Every forged, misdirected or stale token must be rejected with a specific
code; only a correctly signed, correctly bound token yields the immutable
`oid`. Also bounds JWKS refetches an attacker can force with unknown `kid`s.
"""
from __future__ import annotations

import base64
import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from apps.guard.accessproof_guard.identity import IdentityError, OidcVerifier

TENANT = "6479e7ca-b256-4ebc-a408-871b9046547c"
OTHER_TENANT = "00000000-1111-2222-3333-444444444444"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
AUDIENCE = "api://accessproof-guard-test"
ALICE, BOB = "alice-oid-0001", "bob-oid-0002"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ATTACKER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(private, kid):
    pub = private.public_key().public_numbers()

    def b(n: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode().rstrip("=")
    return {"kty": "RSA", "kid": kid, "use": "sig", "n": b(pub.n), "e": b(pub.e)}


class Fetches:
    def __init__(self):
        self.jwks = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": "https://login.microsoftonline.com/keys"})
        self.jwks += 1
        return httpx.Response(200, json={"keys": [_jwk(KEY, "k1")]})


@pytest.fixture()
def verifier():
    f = Fetches()
    v = OidcVerifier(issuer=ISSUER, audience=AUDIENCE, subject_claim="oid", tenant_id=TENANT,
                             client=httpx.Client(transport=httpx.MockTransport(f.handler)))
    v._fetches = f  # type: ignore[attr-defined]
    return v


def _claims(**over):
    now = int(time.time())
    c = {"iss": ISSUER, "aud": AUDIENCE, "tid": TENANT, "oid": ALICE, "sub": "pairwise-alice",
         "iat": now, "nbf": now - 5, "exp": now + 600, "ver": "2.0"}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def _hs256_with_public_jwk():
    """Classic alg-confusion: HMAC-sign with the issuer's PUBLIC key as the secret."""
    import hashlib
    import hmac

    def enc(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
    signing_input = enc({"alg": "HS256", "typ": "JWT", "kid": "k1"}) + "." + enc(_claims())
    secret = json.dumps(_jwk(KEY, "k1")).encode()
    sig = base64.urlsafe_b64encode(hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    return signing_input + "." + sig


def _tok(claims, key=KEY, kid="k1", alg="RS256"):
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


def test_legitimate_alice_and_bob_map_to_their_own_immutable_oid(verifier):
    assert verifier.verify(_tok(_claims())).subject == ALICE
    assert verifier.verify(_tok(_claims(oid=BOB))).subject == BOB


@pytest.mark.parametrize("name,token_factory,code", [
    ("expired", lambda: _tok(_claims(exp=int(time.time()) - 60, iat=int(time.time()) - 700)), "IDENTITY_TOKEN_EXPIRED"),
    ("wrong_tenant", lambda: _tok(_claims(tid=OTHER_TENANT)), "IDENTITY_TENANT_MISMATCH"),
    ("missing_tenant", lambda: _tok(_claims(tid=None)), "IDENTITY_TENANT_MISMATCH"),
    ("wrong_audience_other_app", lambda: _tok(_claims(aud="api://some-other-app")), "IDENTITY_AUDIENCE_MISMATCH"),
    ("graph_access_token", lambda: _tok(_claims(aud="https://graph.microsoft.com")), "IDENTITY_AUDIENCE_MISMATCH"),
    ("wrong_issuer_other_tenant", lambda: _tok(_claims(iss=f"https://login.microsoftonline.com/{OTHER_TENANT}/v2.0")), "IDENTITY_ISSUER_MISMATCH"),
    ("v1_issuer", lambda: _tok(_claims(iss=f"https://sts.windows.net/{TENANT}/")), "IDENTITY_ISSUER_MISMATCH"),
    ("forged_signature", lambda: _tok(_claims(), key=ATTACKER_KEY), "IDENTITY_TOKEN_INVALID"),
    ("unknown_kid", lambda: _tok(_claims(), key=ATTACKER_KEY, kid="attacker"), "IDENTITY_TOKEN_INVALID"),
    ("not_yet_valid", lambda: _tok(_claims(nbf=int(time.time()) + 600)), "IDENTITY_TOKEN_INVALID"),
    ("missing_exp", lambda: _tok(_claims(exp=None)), "IDENTITY_TOKEN_INVALID"),
    ("missing_oid", lambda: _tok(_claims(oid=None)), "IDENTITY_SUBJECT_UNKNOWN"),
    ("alg_none", lambda: jwt.encode(_claims(), None, algorithm="none", headers={"kid": "k1"}), "IDENTITY_TOKEN_INVALID"),
    ("hs256_key_confusion", lambda: _hs256_with_public_jwk(), "IDENTITY_TOKEN_INVALID"),
    ("garbage", lambda: "not.a.jwt", "IDENTITY_TOKEN_INVALID"),
    ("empty", lambda: "", "IDENTITY_TOKEN_INVALID"),
])
def test_every_forged_or_misbound_token_is_rejected(verifier, name, token_factory, code):
    with pytest.raises(IdentityError) as err:
        verifier.verify(token_factory())
    assert str(err.value) == code or getattr(err.value, "code", None) == code or code in str(err.value.args), (name, err.value)


def test_unknown_kid_flood_cannot_force_unbounded_jwks_refetches(verifier):
    verifier.verify(_tok(_claims()))
    baseline = verifier._fetches.jwks  # type: ignore[attr-defined]
    for i in range(50):
        with pytest.raises(IdentityError):
            verifier.verify(_tok(_claims(), key=ATTACKER_KEY, kid=f"attacker-{i}"))
    forced = verifier._fetches.jwks - baseline  # type: ignore[attr-defined]
    assert forced <= 2, f"{forced} JWKS refetches forced by 50 unknown-kid tokens"


def test_key_rotation_is_still_picked_up_after_the_refresh_floor(verifier, monkeypatch):
    verifier.verify(_tok(_claims()))
    rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keys = [_jwk(KEY, "k1"), _jwk(rotated, "k2")]
    f = verifier._fetches  # type: ignore[attr-defined]
    original = f.handler
    f.handler = lambda req: (httpx.Response(200, json={"keys": keys}) if not req.url.path.endswith("configuration")
                             else original(req))
    verifier._client = httpx.Client(transport=httpx.MockTransport(lambda r: f.handler(r)))
    now = time.monotonic()
    monkeypatch.setattr(time, "monotonic", lambda: now + verifier.min_refresh_seconds + 1)
    assert verifier.verify(_tok(_claims(oid=BOB), key=rotated, kid="k2")).subject == BOB
