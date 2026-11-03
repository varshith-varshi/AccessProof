"""End-user identity verification for the local Guard data plane.

The Guard intentionally caches only public OIDC discovery/JWKS material.  It
never sends employee tokens to the control plane and it never falls back from
an OIDC configuration to a shared symmetric key.
"""
from __future__ import annotations

import threading
import time
from ipaddress import ip_address
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt

from packages.connector_sdk.http_target import _pin_https_url


class IdentityError(RuntimeError):
    """A safe, customer-actionable identity failure code."""


@dataclass(frozen=True)
class VerifiedIdentity:
    subject: str
    issuer: str
    tenant_id: str | None
    claims: dict[str, Any]


class OidcVerifier:
    """Bounded, cached OIDC discovery and asymmetric JWT validation."""

    _algorithms = {"RS256", "RS384", "RS512", "ES256", "ES384"}

    @staticmethod
    def _public_https_url(url: str, error_code: str) -> None:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").rstrip(".").lower()
        if (parsed.scheme != "https" or not parsed.netloc or not host
                or parsed.username or parsed.password or parsed.fragment
                or host == "localhost" or host.endswith((".localhost", ".internal", ".local"))):
            raise IdentityError(error_code)
        try:
            address = ip_address(host)
        except ValueError:
            return
        if not address.is_global:
            raise IdentityError(error_code)

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
        required_scope: str | None = None,
    ) -> None:
        # Permissions must follow an immutable issuer-scoped user identifier.
        # Emails, usernames and display names can be reassigned and would
        # silently transfer an old employee's ACL to a new account.
        if subject_claim not in {"sub", "oid"}:
            raise IdentityError("IDENTITY_SUBJECT_CLAIM_UNSAFE")
        # An issuer is an opaque security identifier.  In particular Auth0
        # issuers conventionally end in '/', and removing it merges distinct
        # issuer namespaces.  Preserve the configured value byte-for-byte.
        if not issuer or issuer != issuer.strip():
            raise IdentityError("IDENTITY_ISSUER_INVALID")
        self._public_https_url(issuer, "IDENTITY_ISSUER_INVALID")
        if urlsplit(issuer).query:
            raise IdentityError("IDENTITY_ISSUER_INVALID")
        self.issuer = issuer
        self.audience = audience
        self.subject_claim = subject_claim
        self.tenant_id = tenant_id
        # When set, only a USER-DELEGATED ACCESS TOKEN for this API carrying
        # this scope is accepted: ID tokens (no scp) and app-only tokens
        # (idtyp=app / roles without scp) are rejected.
        self.required_scope = required_scope or None
        self.cache_seconds = max(30.0, cache_seconds)
        self.min_refresh_seconds = min(30.0, self.cache_seconds)
        self._client = client or httpx.Client(timeout=timeout_seconds, follow_redirects=False, trust_env=False)
        self._owns_client = client is None
        self._discovery: tuple[float, dict[str, str]] | None = None
        self._jwks: tuple[float, dict[str, dict[str, Any]]] | None = None
        self._lock = threading.RLock()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _json(self, url: str) -> dict[str, Any]:
        self._public_https_url(url, "IDENTITY_KEY_UNAVAILABLE")
        try:
            if self._owns_client:
                # Pin the already verified public address to the connection
                # while preserving the original Host and TLS SNI. Never let
                # attacker-controlled discovery metadata reach local/metadata
                # IPs, including via DNS rebinding after validation.
                pinned, host, sni = _pin_https_url(url)
                response = self._client.get(
                    pinned,
                    headers={"Accept": "application/json", "Host": host},
                    extensions={"sni_hostname": sni},
                )
            else:
                # Injected mock transports exercise token validation without
                # requiring real DNS for synthetic issuer.example.test.
                response = self._client.get(url, headers={"Accept": "application/json"})
        except ValueError as exc:
            raise IdentityError("IDENTITY_KEY_UNAVAILABLE") from exc
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
            discovery_url = self.issuer + ("" if self.issuer.endswith("/") else "/") + ".well-known/openid-configuration"
            payload = self._json(discovery_url)
            discovered_issuer = payload.get("issuer")
            jwks_uri = payload.get("jwks_uri")
            if not isinstance(discovered_issuer, str) or discovered_issuer != self.issuer:
                raise IdentityError("IDENTITY_ISSUER_MISMATCH")
            if not isinstance(jwks_uri, str):
                raise IdentityError("IDENTITY_KEY_UNAVAILABLE")
            self._public_https_url(jwks_uri, "IDENTITY_KEY_UNAVAILABLE")
            document = {"issuer": discovered_issuer, "jwks_uri": jwks_uri}
            self._discovery = (time.monotonic(), document)
            return document

    def _keys(self, *, refresh: bool = False) -> dict[str, dict[str, Any]]:
        with self._lock:
            age = time.monotonic() - self._jwks[0] if self._jwks else None
            if not refresh and age is not None and age < self.cache_seconds:
                return self._jwks[1]
            # A token's `kid` is attacker-controlled.  Without a floor, every
            # unknown-kid token would force a JWKS fetch from the IdP: an
            # unauthenticated amplification that adds latency to every request
            # and gets the Guard throttled, failing legitimate verification.
            # Rotation is still honoured: a new kid is fetched within the floor.
            if refresh and age is not None and age < self.min_refresh_seconds:
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
        if self.required_scope is not None:
            scopes = claims.get("scp")
            if claims.get("idtyp") == "app" or not isinstance(scopes, str):
                # No delegated scope: an ID token or an application identity,
                # never an employee calling this API.
                raise IdentityError("IDENTITY_NOT_DELEGATED_ACCESS_TOKEN")
            if self.required_scope not in scopes.split():
                raise IdentityError("IDENTITY_SCOPE_MISSING")
        subject = claims.get(self.subject_claim)
        if not isinstance(subject, str) or not subject:
            raise IdentityError("IDENTITY_SUBJECT_UNKNOWN")
        tenant = claims.get("tid")
        return VerifiedIdentity(
            subject=subject,
            issuer=self.issuer,
            tenant_id=tenant if isinstance(tenant, str) and tenant else None,
            claims=claims,
        )
