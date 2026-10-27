from __future__ import annotations

import json
import socket
import time

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from packages.auth.oidc import OidcProviderClient


def test_oidc_discovery_and_signed_id_token_validation(monkeypatch):
    def fake_getaddrinfo(host, port, type=0, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk["kid"] = "key-1"
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": "https://idp.example.com",
            "aud": "client-id",
            "sub": "abc",
            "email": "alice@example.com",
            "iat": now,
            "exp": now + 300,
            "nonce": "nonce-1",
        },
        private,
        algorithm="RS256",
        headers={"kid": "key-1"},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": "https://idp.example.com",
                    "authorization_endpoint": "https://idp.example.com/authorize",
                    "token_endpoint": "https://idp.example.com/token",
                    "jwks_uri": "https://idp.example.com/jwks",
                },
            )
        if request.url.path == "/jwks":
            return httpx.Response(200, json={"keys": [jwk]})
        return httpx.Response(404)

    provider = OidcProviderClient("https://idp.example.com", transport=httpx.MockTransport(handler))
    discovery = provider.discovery()
    claims = provider.validate_id_token(
        discovery, id_token=token, client_id="client-id", nonce="nonce-1"
    )
    provider.close()
    assert claims["sub"] == "abc"
