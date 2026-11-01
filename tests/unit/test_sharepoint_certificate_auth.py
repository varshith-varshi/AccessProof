"""Certificate-bound SharePoint REST app-only OAuth tests; no real credentials."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from packages.auth.microsoft_certificate import (
    SharePointCertificateAuthError,
    create_sharepoint_client_assertion,
    sharepoint_rest_app_token,
)

TENANT = "11111111-2222-3333-4444-555555555555"
APP = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
HOST = "neuralmatrix093.sharepoint.com"


@pytest.fixture
def certificate_material() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic SharePoint cert")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30)).sign(key, hashes.SHA256())
    )
    return (
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        certificate.public_bytes(serialization.Encoding.DER),
    )


def test_signed_assertion_has_exact_tenant_app_audience_and_certificate_thumbprint(certificate_material):
    key, certificate = certificate_material
    endpoint, scope, assertion = create_sharepoint_client_assertion(
        tenant_id=TENANT, client_id=APP, sharepoint_host=HOST,
        private_key_pem=key, public_certificate_der=certificate,
    )
    public_key = x509.load_der_x509_certificate(certificate).public_key()
    decoded = jwt.decode(assertion, public_key, algorithms=["RS256"], audience=endpoint)
    assert decoded["iss"] == APP == decoded["sub"]
    assert decoded["exp"] - decoded["iat"] == 300
    assert scope == "https://neuralmatrix093.sharepoint.com/.default"
    header = jwt.get_unverified_header(assertion)
    assert header["alg"] == "RS256"
    assert header["x5t"] == base64.urlsafe_b64encode(__import__("hashlib").sha1(certificate).digest()).decode().rstrip("=")


@pytest.mark.parametrize("host", [
    "evil.invalid", "neuralmatrix093.sharepoint.com.evil.invalid",
    "neuralmatrix093.sharepoint.com:443", "neuralmatrix093.sharepoint.com/other",
    "user@neuralmatrix093.sharepoint.com", "neuralmatrix093.sharepoint.com?target=evil",
])
def test_invalid_certificate_scope_rejected_before_token_request(certificate_material, host):
    key, certificate = certificate_material
    with pytest.raises(SharePointCertificateAuthError, match="SCOPE_INVALID"):
        create_sharepoint_client_assertion(
            tenant_id=TENANT, client_id=APP, sharepoint_host=host,
            private_key_pem=key, public_certificate_der=certificate,
        )


def test_private_key_cannot_substitute_different_public_certificate(certificate_material):
    key, _ = certificate_material
    _, another_certificate = certificate_material_fixture()
    with pytest.raises(SharePointCertificateAuthError, match="CLIENT_CERTIFICATE_INVALID"):
        create_sharepoint_client_assertion(
            tenant_id=TENANT, client_id=APP, sharepoint_host=HOST,
            private_key_pem=key, public_certificate_der=another_certificate,
        )


def certificate_material_fixture() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Another synthetic cert")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2)).sign(key, hashes.SHA256())
    )
    return (
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        certificate.public_bytes(serialization.Encoding.DER),
    )


@pytest.mark.asyncio
async def test_certificate_oauth_request_signed_and_token_returned_without_logging(
    certificate_material, tmp_path: Path,
):
    key, cert = certificate_material
    key_file, cert_file = tmp_path / "client-private.pem", tmp_path / "client-public.cer"
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    cert_file.write_bytes(cert)
    seen = []
    def respond(req: httpx.Request):
        payload = parse_qs(req.content.decode())
        assert payload["grant_type"] == ["client_credentials"]
        assert payload["scope"] == ["https://" + HOST + "/.default"]
        assert payload["client_assertion_type"] == [
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ]
        assertion = payload["client_assertion"][0]
        decoded = jwt.decode(
            assertion,
            x509.load_der_x509_certificate(cert).public_key(),
            algorithms=["RS256"], audience=str(req.url),
        )
        assert decoded["iss"] == APP
        seen.append(1)
        return httpx.Response(200, json={"access_token": "synthetic-token"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        result = await sharepoint_rest_app_token(
            tenant_id=TENANT, client_id=APP, sharepoint_host=HOST,
            private_key_file=key_file, certificate_der_file=cert_file, client=client,
        )
    assert result == "synthetic-token"
    assert seen == [1]


@pytest.mark.asyncio
async def test_private_key_world_readable_is_rejected(certificate_material, tmp_path):
    key, cert = certificate_material
    key_file, cert_file = tmp_path / "private.pem", tmp_path / "public.cer"
    key_file.write_bytes(key)
    key_file.chmod(0o644)
    cert_file.write_bytes(cert)
    with pytest.raises(SharePointCertificateAuthError, match="NOT_AVAILABLE"):
        await sharepoint_rest_app_token(
            tenant_id=TENANT, client_id=APP, sharepoint_host=HOST,
            private_key_file=key_file, certificate_der_file=cert_file,
        )


@pytest.mark.asyncio
async def test_oauth_provider_rejection_does_not_echo_provider_response(certificate_material, tmp_path):
    key, cert = certificate_material
    key_file, cert_file = tmp_path / "private.pem", tmp_path / "public.cer"
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    cert_file.write_bytes(cert)
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda req: httpx.Response(401, text="sensitive-provider-response-secret")
    )) as client:
        with pytest.raises(SharePointCertificateAuthError, match="TOKEN_REJECTED_HTTP_401") as exc:
            await sharepoint_rest_app_token(
                tenant_id=TENANT, client_id=APP, sharepoint_host=HOST,
                private_key_file=key_file, certificate_der_file=cert_file, client=client,
            )
    assert "sensitive-provider-response-secret" not in str(exc.value)
