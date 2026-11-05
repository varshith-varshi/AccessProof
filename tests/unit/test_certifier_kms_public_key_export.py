from __future__ import annotations

import base64
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from packages.crypto import aws_kms_signer
from scripts.certifier import kms_public_key_export as export


def test_export_is_raw_32_byte_public_key_and_never_signs(monkeypatch):
    key = Ed25519PrivateKey.generate()
    class Signer:
        def public_key(self):
            return key.public_key()
    called = []
    def signer(arn):
        called.append(arn)
        return Signer()
    monkeypatch.setattr(export, 'KmsEd25519Signer', signer)
    result = export.export('arn:aws:kms:eu-north-1:111122223333:key/12345678-abcd-1234-abcd-1234567890ab',
                           'kms-certifier-2026-11')
    b64 = result['kms-certifier-2026-11']
    raw = base64.urlsafe_b64decode(b64 + '=' * (-len(b64) % 4))
    assert raw == key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert len(raw) == 32
    assert len(called) == 1


def test_default_old_key_id_cannot_be_overwritten():
    with pytest.raises(aws_kms_signer.KmsSignerError, match='DISTINCT_KEY_ID_REQUIRED'):
        export.export('not-a-key', 'ap-certifier-2026-11')
