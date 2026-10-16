"""End-user identity verification for the local Guard data plane.

The Guard intentionally caches only public OIDC discovery/JWKS material.  It
never sends employee tokens to the control plane and it never falls back from
an OIDC configuration to a shared symmetric key.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt


class IdentityError(RuntimeError):
    """A safe, customer-actionable identity failure code."""


@dataclass(frozen=True)
class VerifiedIdentity:
    subject: str
    claims: dict[str, Any]


class OidcVerifier:
    """Bounded, cached OIDC discovery and asymmetric JWT validation."""

    _algorithms = {"RS256", "RS384", "RS512", "ES256", "ES384"}

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        subject_claim: str,
        tenant_id: str | None = None,
        cache_seconds: float = 300,
        timeout_seconds: float = 5,
        client: httpx.Client | None = None,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.subject_claim = subject_claim
        self.tenant_id = tenant_id
        self.cache_seconds = max(30.0, cache_seconds)
        self._client = client or httpx.Client(timeout=timeout_seconds, follow_redirects=False, trust_env=False)
        self._owns_client = client is None
        self._discovery: tuple[float, dict[str, str]] | None = None
        self._jwks: tuple[float, dict[str, dict[str, Any]]] | None = None
        self._lock = threading.RLock()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _json(self, url: str) -> dict[str, Any]:
        try:
            response = self._client.get(url, headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise IdentityError("IDENTITY_PROVIDER_UNAVAILABLE") from exc
        if response.status_code >= 500:
            raise IdentityError("IDENTITY_PROVIDER_UNAVAILABLE")
        if response.status_code >= 400:
            raise IdentityError("IDENTITY_KEY_UNAVAILABLE")
        try:
            payload = response.json()
        except ValueError as exc:
            raise IdentityError("IDENTITY_KEY_UNAVAILABLE") from exc
        if not isinstance(payload, dict):
            raise IdentityError("IDENTITY_KEY_UNAVAILABLE")
        return payload

    def _discovery_document(self, *, refresh: bool = False) -> dict[str, str]:
        with self._lock:
            if not refresh and self._discovery and time.monotonic() - self._discovery[0] < self.cache_seconds:
                return self._discovery[1]
            payload = self._json(f"{self.issuer}/.well-known/openid-configuration")
            discovered_issuer = str(payload.get("issuer") or "").rstrip("/")
            jwks_uri = payload.get("jwks_uri")
            if discovered_issuer != self.issuer:
                raise IdentityError("IDENTITY_ISSUER_MISMATCH")
            if not isinstance(jwks_uri, str) or not jwks_uri.startswith("https://"):
                raise IdentityError("IDENTITY_KEY_UNAVAILABLE")
            document = {"issuer": discovered_issuer, "jwks_uri": jwks_uri}
            self._discovery = (time.monotonic(), document)
            return document

    def _keys(self, *, refresh: bool = False) -> dict[str, dict[str, Any]]:
        with self._lock:
            if not refresh and self._jwks and time.monotonic() - self._jwks[0] < self.cache_seconds:
                return self._jwks[1]
            # Key rotation refreshes JWKS only.  Discovery is a separate trust
            # boundary and stays cached until its own TTL expires.
            document = self._discovery_document()
            payload = self._json(document["jwks_uri"])
            keys = payload.get("keys")
            if not isinstance(keys, list):
                raise IdentityError("IDENTITY_KEY_UNAVAILABLE")
            indexed = {
                str(key["kid"]): key
                for key in keys
                if isinstance(key, dict) and isinstance(key.get("kid"), str) and key.get("kty") in {"RSA", "EC"}
            }
            if not indexed:
                raise IdentityError("IDENTITY_KEY_UNAVAILABLE")
            self._jwks = (time.monotonic(), indexed)
            return indexed

    def verify(self, token: str) -> VerifiedIdentity:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise IdentityError("IDENTITY_TOKEN_INVALID") from exc
        algorithm, kid = header.get("alg"), header.get("kid")
        if algorithm not in self._algorithms or not isinstance(kid, str) or not kid:
            raise IdentityError("IDENTITY_TOKEN_INVALID")
        keys = self._keys()
        jwk = keys.get(kid)
        if jwk is None:
            jwk = self._keys(refresh=True).get(kid)
        if jwk is None:
            raise IdentityError("IDENTITY_TOKEN_INVALID")
        try:
            key = jwt.PyJWK.from_dict(jwk, algorithm=algorithm).key
            claims = jwt.decode(
                token,
                key=key,
                algorithms=[algorithm],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise IdentityError("IDENTITY_TOKEN_EXPIRED") from exc
        except jwt.InvalidIssuerError as exc:
            raise IdentityError("IDENTITY_ISSUER_MISMATCH") from exc
        except jwt.InvalidAudienceError as exc:
            raise IdentityError("IDENTITY_AUDIENCE_MISMATCH") from exc
        except jwt.ImmatureSignatureError as exc:
            raise IdentityError("IDENTITY_TOKEN_INVALID") from exc
        except jwt.PyJWTError as exc:
            raise IdentityError("IDENTITY_TOKEN_INVALID") from exc
        if self.tenant_id and claims.get("tid") != self.tenant_id:
            raise IdentityError("IDENTITY_TENANT_MISMATCH")
        subject = claims.get(self.subject_claim)
        if not isinstance(subject, str) or not subject:
            raise IdentityError("IDENTITY_SUBJECT_UNKNOWN")
        return VerifiedIdentity(subject=subject, claims=claims)
