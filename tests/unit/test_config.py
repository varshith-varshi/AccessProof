import pytest
from apps.api.accessproof_api.config import Settings, validate_production_settings


def test_production_rejects_development_secrets_and_sqlite():
    unsafe = Settings(
        env="production",
        database_url="sqlite:///prod.db",
        web_origin="http://example.com",
        session_hmac_key="development-only-change-me-session-key",
        secret_encryption_key="development-only-change-me-secret-key",
        report_signing_key="development-only-change-me-report-signing-key",
    )
    with pytest.raises(RuntimeError) as exc:
        validate_production_settings(unsafe)
    message = str(exc.value)
    assert "SQLite" in message and "HTTPS" in message and "REPORT_SIGNING_KEY" in message


def test_production_accepts_nondefault_hardened_settings():
    safe = Settings(
        env="production",
        database_url="postgresql+psycopg://user:pass@db/accessproof",
        redis_url="redis://redis:6379/0",
        web_origin="https://accessproof.example",
        cors_allowed_origins=("https://accessproof.example",),
        session_hmac_key="session-secret-long-random-value",
        secret_encryption_key="encryption-secret-long-random-value",
        report_signing_key="signing-secret-long-random-value",
        public_app_url="https://accessproof.example",
        api_public_url="https://api.accessproof.example",
        email_delivery_mode="smtp",
        email_from="noreply@accessproof.example",
        smtp_host="smtp.example",
        allowed_hosts=("accessproof.example",),
    )
    validate_production_settings(safe)


def test_production_rejects_weak_secrets_and_wildcard_hosts():
    unsafe = Settings(
        env="production",
        database_url="postgresql+psycopg://user:pass@db/accessproof",
        redis_url="redis://redis:6379/0",
        web_origin="https://accessproof.example",
        cors_allowed_origins=("https://accessproof.example",),
        session_hmac_key="change-me",
        secret_encryption_key="placeholder-secret",
        report_signing_key="example-signing-key",
        public_app_url="https://accessproof.example",
        api_public_url="https://api.accessproof.example",
        email_delivery_mode="smtp",
        smtp_host="smtp.example",
        allowed_hosts=("*",),
        rls_bypass=True,
    )
    with pytest.raises(RuntimeError) as exc:
        validate_production_settings(unsafe)
    message = str(exc.value)
    assert "SESSION_HMAC_KEY" in message
    assert "ACCESSPROOF_ALLOWED_HOSTS" in message
    assert "RLS_BYPASS" in message


def test_production_rejects_non_https_cors_and_api_urls():
    unsafe = Settings(
        env="production",
        database_url="postgresql+psycopg://user:pass@db/accessproof",
        redis_url="redis://redis:6379/0",
        web_origin="https://app.accessproof.example",
        cors_allowed_origins=("http://app.accessproof.example",),
        session_hmac_key="session-secret-long-random-value",
        secret_encryption_key="encryption-secret-long-random-value",
        report_signing_key="signing-secret-long-random-value",
        public_app_url="https://app.accessproof.example",
        api_public_url="http://api.accessproof.example",
        email_delivery_mode="smtp",
        smtp_host="smtp.example",
        allowed_hosts=("api.accessproof.example",),
    )
    with pytest.raises(RuntimeError) as exc:
        validate_production_settings(unsafe)
    assert "CORS_ALLOWED_ORIGINS" in str(exc.value)
    assert "API_PUBLIC_URL" in str(exc.value)
