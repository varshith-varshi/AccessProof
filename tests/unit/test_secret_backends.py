import pytest

from apps.api.accessproof_api.config import Settings, validate_production_settings
from packages.crypto.secrets import AwsKmsSecretBackend, SecretBackendError, build_secret_backend


class FakeKms:
    def __init__(self):
        self.key = bytes(range(32))
        self.generated = 0
        self.decrypted = 0
        self.described = 0

    def generate_data_key(self, *, KeyId, KeySpec):
        assert KeyId == "alias/accessproof"
        assert KeySpec == "AES_256"
        self.generated += 1
        return {
            "Plaintext": self.key,
            "CiphertextBlob": b"kms-wrapped-key",
            "KeyId": "arn:aws:kms:us-east-1:123:key/abc",
        }

    def decrypt(self, *, CiphertextBlob, KeyId):
        assert CiphertextBlob == b"kms-wrapped-key"
        assert KeyId == "alias/accessproof"
        self.decrypted += 1
        return {"Plaintext": self.key}

    def describe_key(self, *, KeyId):
        assert KeyId == "alias/accessproof"
        self.described += 1
        return {
            "KeyMetadata": {
                "Enabled": True,
                "KeyState": "Enabled",
                "Arn": "arn:aws:kms:us-east-1:123:key/abc",
            }
        }


def test_aws_kms_envelope_round_trip_and_health():
    client = FakeKms()
    backend = AwsKmsSecretBackend(key_id="alias/accessproof", client=client)
    ciphertext = backend.encrypt("provider-refresh-token")

    assert ciphertext.startswith("awskms:v1:")
    assert "provider-refresh-token" not in ciphertext
    assert backend.decrypt(ciphertext) == "provider-refresh-token"
    health = backend.health_check()
    assert health["backend"] == "aws-kms"
    assert health["status"] == "ok"
    assert health["key_id"].endswith(":key/abc")
    assert (client.generated, client.decrypted, client.described) == (1, 1, 1)


def test_aws_kms_backend_rejects_local_ciphertext():
    backend = AwsKmsSecretBackend(key_id="alias/accessproof", client=FakeKms())
    with pytest.raises(SecretBackendError, match="not produced"):
        backend.decrypt("legacy-local-ciphertext")


def test_backend_factory_preserves_local_compatibility():
    backend = build_secret_backend(backend="local", local_key="unit-test-key")
    ciphertext = backend.encrypt("secret")
    assert backend.decrypt(ciphertext) == "secret"


def test_production_allows_aws_kms_without_local_master_key():
    settings = Settings(
        env="production",
        database_url="postgresql+psycopg://u:p@db/accessproof",
        redis_url="redis://redis:6379/0",
        web_origin="https://accessproof.example",
        cors_allowed_origins=("https://accessproof.example",),
        session_hmac_key="a-unique-session-secret-with-32-plus-chars",
        secret_encryption_key="development-only-change-me-secret-key",
        secret_backend="aws-kms",
        aws_kms_key_id="alias/accessproof",
        report_signing_key="a-unique-report-signing-secret-32-plus",
        public_app_url="https://accessproof.example",
        api_public_url="https://api.accessproof.example",
        email_delivery_mode="smtp",
        smtp_host="smtp.example",
        allowed_hosts=("accessproof.example",),
    )
    validate_production_settings(settings)


def test_production_rejects_aws_kms_without_key_id():
    settings = Settings(
        env="production",
        database_url="postgresql+psycopg://u:p@db/accessproof",
        redis_url="redis://redis:6379/0",
        web_origin="https://accessproof.example",
        session_hmac_key="strong-session-secret",
        secret_encryption_key="not-used-by-kms",
        secret_backend="aws-kms",
        aws_kms_key_id=None,
        report_signing_key="strong-report-key",
        public_app_url="https://accessproof.example",
        email_delivery_mode="smtp",
        smtp_host="smtp.example",
    )
    with pytest.raises(RuntimeError, match="AWS_KMS_KEY_ID"):
        validate_production_settings(settings)
