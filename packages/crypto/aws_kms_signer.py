"""Optional isolated Ed25519 KMS signer for the independent AccessProof certifier.

No new key or AWS resource is created here. Never import this in the API image
as a signer. This adapter uses pure Ed25519 (RAW) and fails closed if KMS cannot
produce a signature with the exact reviewed key/algorithm. Caller still must
independently observe every source/route certification evidence check.
"""
from __future__ import annotations

import os
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_KMS_ARN = re.compile(r"^arn:aws:kms:eu-north-1:[0-9]{12}:key/[0-9a-fA-F-]{36}$")
_ALGO = "ED25519_SHA_512"
_LIMIT = 4096


class KmsSignerError(RuntimeError):
    """Never downgrade to an unapproved local key on KMS failure."""


class KmsEd25519Signer:
    """Ed25519PrivateKey-compatible public_key() and sign() only; key stays in KMS."""

    def __init__(self, key_arn: str, *, client: Any = None) -> None:
        if not _KMS_ARN.fullmatch(key_arn):
            raise KmsSignerError("KMS_KEY_MUST_BE_PINNED_EU_NORTH_1_ARN")
        if os.environ.get("AWS_PROFILE") != "accessproof-certifier" or any(
            os.environ.get(name) for name in (
                "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                "AWS_SECURITY_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE",
            )
        ):
            raise KmsSignerError("KMS_REQUIRES_INDEPENDENT_CERTIFIER_PROFILE")
        if client is None:
            try:
                import boto3  # optional aws-kms extra, never required by API images
            except ImportError as exc:
                raise KmsSignerError("AWS_KMS_DEPENDENCY_MISSING") from exc
            client = boto3.Session(profile_name="accessproof-certifier", region_name="eu-north-1").client("kms")
        try:
            result = client.get_public_key(KeyId=key_arn)
            if (result.get("KeyId") != key_arn
                or result.get("KeySpec") != "ECC_NIST_EDWARDS25519"
                or result.get("KeyUsage") != "SIGN_VERIFY"
                or _ALGO not in result.get("SigningAlgorithms", ())):
                raise KmsSignerError("KMS_KEY_TYPE_OR_USAGE_NOT_APPROVED")
            public = serialization.load_der_public_key(result["PublicKey"])
            if not isinstance(public, Ed25519PublicKey):
                raise KmsSignerError("KMS_PUBLIC_KEY_NOT_ED25519")
        except KmsSignerError:
            raise
        except Exception as exc:
            raise KmsSignerError("KMS_PUBLIC_KEY_UNAVAILABLE") from exc
        self._key_arn = key_arn
        self._client = client
        self._public = public

    def public_key(self) -> Ed25519PublicKey:
        return self._public

    def sign(self, data: bytes) -> bytes:
        if not isinstance(data, bytes) or len(data) > _LIMIT:
            # KMS's PH variant is NOT byte-compatible with pure Ed25519.
            raise KmsSignerError("KMS_ED25519_RAW_MESSAGE_TOO_LARGE")
        try:
            result = self._client.sign(KeyId=self._key_arn, Message=data,
                                       MessageType="RAW", SigningAlgorithm=_ALGO)
            raw = result.get("Signature")
            if (result.get("KeyId") != self._key_arn
                or result.get("SigningAlgorithm") != _ALGO
                or not isinstance(raw, bytes) or len(raw) != 64):
                raise KmsSignerError("KMS_SIGNING_RESPONSE_INVALID")
            self._public.verify(raw, data)
            return raw
        except KmsSignerError:
            raise
        except InvalidSignature as exc:
            raise KmsSignerError("KMS_SIGNING_SIGNATURE_INVALID") from exc
        except Exception as exc:
            raise KmsSignerError("KMS_SIGNING_UNAVAILABLE") from exc
