from __future__ import annotations

from typing import Any

import base64
import hashlib
import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


@dataclass(frozen=True, slots=True)
class SignedManifest:
    algorithm: str
    key_id: str
    payload_sha256: str
    public_key: str
    signature: str

    def as_dict(self) -> dict[str, str]:
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "payload_sha256": self.payload_sha256,
            "public_key": self.public_key,
            "signature": self.signature,
        }


class Ed25519Signer:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key
        self._public_key = private_key.public_key()
        public_raw = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = "ed25519:" + hashlib.sha256(public_raw).hexdigest()[:16]

    @classmethod
    def from_secret(cls, secret: str) -> "Ed25519Signer":
        seed = hashlib.sha256(secret.encode("utf-8")).digest()
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    def sign(self, payload: dict[str, Any]) -> SignedManifest:
        canonical = canonical_json(payload)
        signature = self._private_key.sign(canonical)
        public_raw = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return SignedManifest(
            algorithm="Ed25519",
            key_id=self.key_id,
            payload_sha256=hashlib.sha256(canonical).hexdigest(),
            public_key=base64.urlsafe_b64encode(public_raw).decode("ascii"),
            signature=base64.urlsafe_b64encode(signature).decode("ascii"),
        )


def verify_manifest(payload: dict[str, Any], manifest: dict[str, Any]) -> bool:
    if manifest.get("algorithm") != "Ed25519":
        return False
    canonical = canonical_json(payload)
    if hashlib.sha256(canonical).hexdigest() != manifest.get("payload_sha256"):
        return False
    try:
        public_raw = base64.urlsafe_b64decode(str(manifest["public_key"]).encode("ascii"))
        signature = base64.urlsafe_b64decode(str(manifest["signature"]).encode("ascii"))
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, canonical)
        expected_key_id = "ed25519:" + hashlib.sha256(public_raw).hexdigest()[:16]
        return expected_key_id == manifest.get("key_id")
    except (KeyError, ValueError, InvalidSignature):
        return False
