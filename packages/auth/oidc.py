from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

from packages.connector_sdk.http_target import _pin_https_url, validate_cloud_url


class OidcError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class OidcDiscovery:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


class OidcProviderClient:
    def __init__(
        self,
        issuer_url: str,
        *,
        timeout_seconds: float = 15.0,
        transport: httpx.BaseTransport | None = None,
    ):
        self.issuer_url = issuer_url.rstrip("/")
        validate_cloud_url(self.issuer_url)
        self._client = httpx.Client(
            timeout=timeout_seconds, follow_redirects=False, trust_env=False, transport=transport
        )

    def close(self) -> None:
        self._client.close()

    def _get_json(self, url: str) -> dict[str, Any]:
        validate_cloud_url(url)
        pinned, host, sni = _pin_https_url(url)
        response = self._client.get(
            pinned,
            headers={"Host": host, "Accept": "application/json"},
            extensions={"sni_hostname": sni},
        )
        if response.status_code >= 400:
            raise OidcError(f"OIDC provider returned HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise OidcError("OIDC provider returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise OidcError("OIDC provider returned invalid JSON object")
        return payload

    def discovery(self) -> OidcDiscovery:
        payload = self._get_json(f"{self.issuer_url}/.well-known/openid-configuration")
        issuer = str(payload.get("issuer") or "").rstrip("/")
        if issuer != self.issuer_url:
            raise OidcError("OIDC discovery issuer does not match configured issuer")
        values = {
            "authorization_endpoint": str(payload.get("authorization_endpoint") or ""),
            "token_endpoint": str(payload.get("token_endpoint") or ""),
            "jwks_uri": str(payload.get("jwks_uri") or ""),
        }
        for name, value in values.items():
            if not value:
                raise OidcError(f"OIDC discovery missing {name}")
            validate_cloud_url(value)
        return OidcDiscovery(issuer=issuer, **values)

    @staticmethod
    def new_pkce() -> tuple[str, str]:
        verifier = secrets.token_urlsafe(48)
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return verifier, challenge

    @staticmethod
    def authorization_url(
        discovery: OidcDiscovery,
        *,
        client_id: str,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_challenge: str,
    ) -> str:
        query = urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": "openid email profile",
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{discovery.authorization_endpoint}?{query}"

    def exchange_code(
        self,
        discovery: OidcDiscovery,
        *,
        client_id: str,
        client_secret: str,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        pinned, host, sni = _pin_https_url(discovery.token_endpoint)
        response = self._client.post(
            pinned,
            headers={"Host": host, "Accept": "application/json"},
            extensions={"sni_hostname": sni},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
                "code_verifier": code_verifier,
            },
        )
        if response.status_code >= 400:
            raise OidcError(f"OIDC token exchange failed with HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise OidcError("OIDC token endpoint returned invalid JSON") from exc
        if not isinstance(payload, dict) or not payload.get("id_token"):
            raise OidcError("OIDC token response did not contain id_token")
        return payload

    def validate_id_token(
        self,
        discovery: OidcDiscovery,
        *,
        id_token: str,
        client_id: str,
        nonce: str,
    ) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise OidcError("Invalid OIDC ID token header") from exc
        kid = header.get("kid")
        alg = header.get("alg")
        if not kid or alg not in {"RS256", "RS384", "RS512", "ES256", "ES384"}:
            raise OidcError("OIDC ID token uses an unsupported signing key/algorithm")
        jwks = self._get_json(discovery.jwks_uri)
        keys = jwks.get("keys")
        if not isinstance(keys, list):
            raise OidcError("OIDC JWKS payload is invalid")
        jwk = next(
            (item for item in keys if isinstance(item, dict) and item.get("kid") == kid), None
        )
        if jwk is None:
            raise OidcError("OIDC signing key was not found in JWKS")
        try:
            key = jwt.PyJWK.from_dict(jwk, algorithm=alg).key
            claims = jwt.decode(
                id_token,
                key=key,
                algorithms=[alg],
                audience=client_id,
                issuer=discovery.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise OidcError("OIDC ID token validation failed") from exc
        if claims.get("nonce") != nonce:
            raise OidcError("OIDC nonce mismatch")
        return claims
