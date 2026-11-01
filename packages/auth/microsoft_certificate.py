"""Certificate-based Microsoft Entra client credentials for SharePoint REST.

Microsoft SharePoint REST/CSOM rejects client-secret app-only tokens.
This module deliberately uses a short-lived signed certificate assertion.
It never logs assertions, tokens, certificate private keys or OAuth responses.
"""
from __future__ import annotations

import base64
import hashlib
import os
import stat
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class SharePointCertificateAuthError(RuntimeError):
    """No sensitive provider/token details are included in this exception."""


def _validate_identity(tenant_id: str, client_id: str, host: str) -> tuple[str, str, str]:
    try:
        tenant = str(UUID(tenant_id))
        client = str(UUID(client_id))
        # Do not accept an arbitrary OAuth scope supplied by a customer.
        raw = urlsplit("https://" + host)
        if (raw.hostname is None or not raw.hostname.endswith(".sharepoint.com")
                or raw.hostname == ".sharepoint.com" or raw.hostname == "sharepoint.com"
                or raw.port is not None or raw.path or raw.query or raw.fragment
                or raw.username or raw.password or not host.isascii()):
            raise ValueError("untrusted host")
    except (ValueError, TypeError, AttributeError) as exc:
        raise SharePointCertificateAuthError("SHAREPOINT_CERTIFICATE_AUTH_SCOPE_INVALID") from exc
    return tenant, client, host.lower()


def create_sharepoint_client_assertion(
    *, tenant_id: str, client_id: str, sharepoint_host: str,
    private_key_pem: bytes, public_certificate_der: bytes,
    now: datetime | None = None,
) -> tuple[str, str, str]:
    """Build assertion; returned JWT is sensitive and must NEVER be logged.

    This is an authentication primitive, not a permission grant or a source
    authorization/certification decision. External provider checks are still
    required before any Protect release.
    """
    tenant, client, host = _validate_identity(tenant_id, client_id, sharepoint_host)
    try:
        cert = x509.load_der_x509_certificate(public_certificate_der)
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 2048:
            raise ValueError("RSA key too small")
        public_key = cert.public_key()
        if (not isinstance(public_key, rsa.RSAPublicKey)
                or public_key.public_numbers() != private_key.public_key().public_numbers()):
            raise ValueError("certificate / key mismatch")
        timestamp = now or datetime.now(timezone.utc)
        if timestamp.tzinfo is None:
            raise ValueError("timezone required")
        current = timestamp.astimezone(timezone.utc)
        if not cert.not_valid_before_utc <= current < cert.not_valid_after_utc:
            raise ValueError("certificate not currently valid")
    except (ValueError, TypeError) as exc:
        raise SharePointCertificateAuthError("SHAREPOINT_CLIENT_CERTIFICATE_INVALID") from exc
    endpoint = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    certificate_thumbprint = base64.urlsafe_b64encode(
        hashlib.sha1(public_certificate_der).digest(),
    ).decode().rstrip("=")
    assert isinstance(private_key, rsa.RSAPrivateKey)
    assertion = jwt.encode(
        {
            "aud": endpoint, "iss": client, "sub": client,
            "jti": secrets.token_urlsafe(22), "iat": int(current.timestamp()),
            "nbf": int(current.timestamp()) - 5,
            "exp": int((current + timedelta(minutes=5)).timestamp()),
        },
        private_key_pem,
        algorithm="RS256",
        headers={"x5t": certificate_thumbprint, "typ": "JWT"},
    )
    return endpoint, f"https://{host}/.default", assertion


async def sharepoint_rest_app_token(
    *,
    tenant_id: str, client_id: str, sharepoint_host: str,
    private_key_file: Path, certificate_der_file: Path,
    client: httpx.AsyncClient | None = None,
) -> str:
    try:
        if private_key_file.is_symlink() or certificate_der_file.is_symlink():
            raise ValueError("symlinked certificate path")
        if os.name == "posix" and stat.S_IMODE(private_key_file.stat().st_mode) & 0o077:
            raise ValueError("private key permissions too broad")
        key = private_key_file.read_bytes()
        certificate = certificate_der_file.read_bytes()
    except (OSError, ValueError) as exc:
        raise SharePointCertificateAuthError("SHAREPOINT_CLIENT_CERTIFICATE_NOT_AVAILABLE") from exc
    endpoint, scope, assertion = create_sharepoint_client_assertion(
        tenant_id=tenant_id, client_id=client_id, sharepoint_host=sharepoint_host,
        private_key_pem=key, public_certificate_der=certificate,
    )
    owns_client = client is None
    session = client or httpx.AsyncClient(timeout=15, trust_env=False, follow_redirects=False)
    try:
        try:
            response = await session.post(
                endpoint,
                data={
                    "client_id": client_id,
                    "scope": scope,
                    "grant_type": "client_credentials",
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": assertion,
                },
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise SharePointCertificateAuthError("SHAREPOINT_CERTIFICATE_TOKEN_ENDPOINT_UNAVAILABLE") from exc
        if response.status_code != 200:
            # Never echo Azure error responses; they can include sensitive tenant metadata.
            raise SharePointCertificateAuthError(
                f"SHAREPOINT_CERTIFICATE_TOKEN_REJECTED_HTTP_{response.status_code}"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise SharePointCertificateAuthError("SHAREPOINT_CERTIFICATE_TOKEN_INVALID") from exc
        token = body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise SharePointCertificateAuthError("SHAREPOINT_CERTIFICATE_TOKEN_INVALID")
        return token
    finally:
        if owns_client:
            await session.aclose()
