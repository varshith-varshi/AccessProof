from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Protocol, runtime_checkable, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretBackendError(RuntimeError):
    """Raised when the configured secret backend cannot encrypt/decrypt safely."""


@runtime_checkable
class SecretBackend(Protocol):
    backend_name: str

    def encrypt(self, plaintext: str, *, aad: bytes = b"accessproof-secret-v1") -> str: ...
    def decrypt(self, ciphertext: str, *, aad: bytes = b"accessproof-secret-v1") -> str: ...
    def health_check(self) -> dict[str, str]: ...


class SecretBox:
    """Backward-compatible local AES-GCM secret backend.

    Existing AccessProof ciphertexts are raw URL-safe base64, so local mode keeps
    that representation to avoid forcing a data migration merely to upgrade the
    secret-management abstraction.
    """

    backend_name = "local-aesgcm"

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("SecretBox key must be exactly 32 bytes")
        self._key = key

    @classmethod
    def from_text(cls, value: str) -> "SecretBox":
        try:
            raw = base64.urlsafe_b64decode(value.encode())
        except Exception:
            raw = b""
        if len(raw) != 32:
            raw = hashlib.sha256(value.encode()).digest()
        return cls(raw)

    def encrypt(self, plaintext: str, *, aad: bytes = b"accessproof-secret-v1") -> str:
        nonce = os.urandom(12)
        encrypted = AESGCM(self._key).encrypt(nonce, plaintext.encode(), aad)
        return base64.urlsafe_b64encode(nonce + encrypted).decode()

    def decrypt(self, ciphertext: str, *, aad: bytes = b"accessproof-secret-v1") -> str:
        raw = base64.urlsafe_b64decode(ciphertext.encode())
        nonce, encrypted = raw[:12], raw[12:]
        return AESGCM(self._key).decrypt(nonce, encrypted, aad).decode()

    def health_check(self) -> dict[str, str]:
        return {"backend": self.backend_name, "status": "ok"}


@dataclass(slots=True)
class AwsKmsSecretBackend:
    """AWS KMS envelope-encryption backend.

    Each secret gets a fresh AES-256 data key from KMS. Only the KMS-encrypted
    data key is persisted alongside the AES-GCM ciphertext; plaintext data keys
    never leave process memory and are discarded after the operation.
    """

    key_id: str
    region_name: str | None = None
    client: Any | None = None
    backend_name: str = "aws-kms"

    _PREFIX = "awskms:v1:"

    def __post_init__(self) -> None:
        if not self.key_id:
            raise ValueError("AWS KMS key_id is required")
        if self.client is None:
            try:
                import boto3  # type: ignore
            except ImportError as exc:  # pragma: no cover - depends on install extras
                raise SecretBackendError(
                    "AWS KMS backend requires boto3; install AccessProof with the aws-kms extra"
                ) from exc
            self.client = boto3.client("kms", region_name=self.region_name)

    @staticmethod
    def _b64(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode()

    @staticmethod
    def _unb64(value: str) -> bytes:
        return base64.urlsafe_b64decode(value.encode())

    def encrypt(self, plaintext: str, *, aad: bytes = b"accessproof-secret-v1") -> str:
        try:
            assert self.client is not None
            result = self.client.generate_data_key(KeyId=self.key_id, KeySpec="AES_256")
            data_key = bytes(result["Plaintext"])
            encrypted_key = bytes(result["CiphertextBlob"])
            key_arn = str(result.get("KeyId") or self.key_id)
        except Exception as exc:
            raise SecretBackendError("AWS KMS generate_data_key failed") from exc
        if len(data_key) != 32:
            raise SecretBackendError("AWS KMS returned an invalid AES-256 data key")
        nonce = os.urandom(12)
        encrypted = AESGCM(data_key).encrypt(nonce, plaintext.encode(), aad)
        envelope = {
            "backend": self.backend_name,
            "key_id": key_arn,
            "encrypted_data_key": self._b64(encrypted_key),
            "nonce": self._b64(nonce),
            "ciphertext": self._b64(encrypted),
        }
        payload = base64.urlsafe_b64encode(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        return self._PREFIX + payload

    def decrypt(self, ciphertext: str, *, aad: bytes = b"accessproof-secret-v1") -> str:
        if not ciphertext.startswith(self._PREFIX):
            raise SecretBackendError("Ciphertext was not produced by the AWS KMS backend")
        try:
            raw = base64.urlsafe_b64decode(ciphertext[len(self._PREFIX) :].encode())
            envelope = json.loads(raw.decode())
            encrypted_key = self._unb64(str(envelope["encrypted_data_key"]))
            nonce = self._unb64(str(envelope["nonce"]))
            encrypted = self._unb64(str(envelope["ciphertext"]))
            assert self.client is not None
            result = self.client.decrypt(
                CiphertextBlob=encrypted_key,
                KeyId=self.key_id,
            )
            data_key = bytes(result["Plaintext"])
            if len(data_key) != 32:
                raise SecretBackendError("AWS KMS returned an invalid decrypted data key")
            return AESGCM(data_key).decrypt(nonce, encrypted, aad).decode()
        except SecretBackendError:
            raise
        except Exception as exc:
            raise SecretBackendError("AWS KMS secret decryption failed") from exc

    def health_check(self) -> dict[str, str]:
        try:
            assert self.client is not None
            result = self.client.describe_key(KeyId=self.key_id)
            meta = result.get("KeyMetadata") or {}
            enabled = bool(meta.get("Enabled", False))
            state = str(meta.get("KeyState") or "UNKNOWN")
            actual_key_id = str(meta.get("Arn") or meta.get("KeyId") or self.key_id)
        except Exception as exc:
            raise SecretBackendError("AWS KMS health check failed") from exc
        if not enabled or state not in {"Enabled", "PendingImport"}:
            raise SecretBackendError(f"AWS KMS key is not usable: state={state}")
        return {
            "backend": self.backend_name,
            "status": "ok",
            "key_id": actual_key_id,
            "key_state": state,
        }


def build_secret_backend(
    *,
    backend: str,
    local_key: str,
    aws_kms_key_id: str | None = None,
    aws_region: str | None = None,
    aws_kms_client: Any | None = None,
) -> SecretBackend:
    normalized = backend.strip().lower()
    if normalized in {"local", "aesgcm", "local-aesgcm"}:
        return SecretBox.from_text(local_key)
    if normalized in {"aws-kms", "aws_kms", "kms"}:
        if not aws_kms_key_id:
            raise ValueError("AWS_KMS_KEY_ID is required for ACCESSPROOF_SECRET_BACKEND=aws-kms")
        return AwsKmsSecretBackend(
            key_id=aws_kms_key_id,
            region_name=aws_region,
            client=aws_kms_client,
        )
    raise ValueError(f"Unsupported secret backend: {backend}")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
