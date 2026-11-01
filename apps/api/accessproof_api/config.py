from __future__ import annotations

import os
from dataclasses import dataclass


GOOGLE_WORKSPACE_DRIVE_V1 = "google-workspace-drive"


class V1ProviderScopeError(ValueError):
    """Raised when a new production V1 source is outside the released scope."""


def _csv_env(name: str, default: str) -> tuple[str, ...]:
    return tuple(value.strip().rstrip("/") for value in os.getenv(name, default).split(",") if value.strip())


@dataclass(frozen=True)
class Settings:
    env: str = os.getenv("ACCESSPROOF_ENV", "development")
    product_name: str = os.getenv("ACCESSPROOF_PRODUCT_NAME", "AccessProof")
    company_name: str = os.getenv("ACCESSPROOF_COMPANY_NAME", "AccessProof Labs")
    support_url: str = os.getenv("ACCESSPROOF_SUPPORT_URL", "https://example.invalid/support")
    support_email: str = os.getenv("ACCESSPROOF_SUPPORT_EMAIL", "support@example.invalid")
    # The current Guard product can move to a clean database without deleting
    # the legacy campaign/run database.  DATABASE_URL remains a compatible
    # fallback for existing installations and test environments.
    database_url: str = os.getenv(
        "ACCESSPROOF_CURRENT_DATABASE_URL",
        os.getenv("DATABASE_URL", "sqlite:///./accessproof.db"),
    )
    redis_url: str | None = os.getenv("REDIS_URL")
    web_origin: str = os.getenv("WEB_ORIGIN", "http://localhost:3000")
    cors_allowed_origins: tuple[str, ...] = _csv_env("CORS_ALLOWED_ORIGINS", os.getenv("WEB_ORIGIN", "http://localhost:3000"))
    allowed_hosts: tuple[str, ...] = _csv_env("ACCESSPROOF_ALLOWED_HOSTS", "*")
    session_hmac_key: str = os.getenv("SESSION_HMAC_KEY", "development-only-change-me-session-key")
    secret_encryption_key: str = os.getenv(
        "SECRET_ENCRYPTION_KEY", "development-only-change-me-secret-key"
    )
    secret_backend: str = os.getenv("ACCESSPROOF_SECRET_BACKEND", "local")
    aws_kms_key_id: str | None = os.getenv("ACCESSPROOF_AWS_KMS_KEY_ID")
    aws_region: str | None = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
    report_signing_key: str = os.getenv(
        "REPORT_SIGNING_KEY", "development-only-change-me-report-signing-key"
    )
    public_app_url: str = os.getenv("ACCESSPROOF_PUBLIC_APP_URL", "http://localhost:3000")
    api_public_url: str = os.getenv("API_PUBLIC_URL", "http://127.0.0.1:8000")
    oidc_redirect_uri: str | None = os.getenv("ACCESSPROOF_OIDC_REDIRECT_URI")
    email_delivery_mode: str = os.getenv("ACCESSPROOF_EMAIL_MODE", "console")
    email_from: str = os.getenv("ACCESSPROOF_EMAIL_FROM", "noreply@example.invalid")
    smtp_host: str | None = os.getenv("ACCESSPROOF_SMTP_HOST")
    smtp_port: int = int(os.getenv("ACCESSPROOF_SMTP_PORT", "587"))
    smtp_username: str | None = os.getenv("ACCESSPROOF_SMTP_USERNAME")
    smtp_password: str | None = os.getenv("ACCESSPROOF_SMTP_PASSWORD")
    smtp_starttls: bool = os.getenv("ACCESSPROOF_SMTP_STARTTLS", "1").lower() not in {
        "0",
        "false",
        "no",
    }
    minimum_runner_version: str = os.getenv("ACCESSPROOF_MIN_RUNNER_VERSION", "0.1.0")
    runner_offline_seconds: int = int(os.getenv("ACCESSPROOF_RUNNER_OFFLINE_SECONDS", "90"))
    retention_sweep_seconds: int = int(os.getenv("ACCESSPROOF_RETENTION_SWEEP_SECONDS", "3600"))
    rls_bypass: bool = os.getenv("ACCESSPROOF_RLS_BYPASS", "0").lower() in {"1", "true", "yes"}
    # Development keeps legacy connectors for compatibility coverage. The
    # production V1 contract is enforced server-side below.
    v1_provider: str = os.getenv("ACCESSPROOF_V1_PROVIDER", GOOGLE_WORKSPACE_DRIVE_V1).strip().lower()
    # Explicit opt-in to create Microsoft sources for Shadow observations only.
    microsoft_shadow_onboarding: bool = os.getenv(
        "ACCESSPROOF_MICROSOFT_SHADOW_ONBOARDING_ENABLED", "0"
    ).strip().lower() in {"1", "true", "yes"}
    microsoft_certified_protect: bool = os.getenv(
        "ACCESSPROOF_MICROSOFT_CERTIFIED_PROTECT_ENABLED", "0"
    ).strip().lower() in {"1", "true", "yes"}


def certified_sharepoint_scope_allowed(
    provider: str,
    *,
    provider_profile: str | None,
    certificate_verified: bool,
    feature_enabled: bool,
) -> bool:
    """Allow *exact* individually certified SharePoint ACL profiles only.

    Older Microsoft-connected sources use the canonical ``microsoft365``
    provider, which also covers OneDrive. The independently verified profile
    must therefore match SharePoint list-item effective access exactly. Never
    allow a Microsoft365/OneDrive source merely from the feature flag.
    """
    return (
        provider in {"sharepoint", "microsoft365"}
        and provider_profile == "sharepoint_list_item_effective"
        and certificate_verified is True
        and feature_enabled is True
    )


settings = Settings()


def v1_source_provider_allowed(provider: str, value: Settings = settings) -> bool:
    """Return whether a *new* source is allowed by the deployed V1 contract."""
    if value.env != "production":
        return True
    return (
        value.v1_provider == GOOGLE_WORKSPACE_DRIVE_V1
        and provider == "google-drive"  # canonical persisted value required by workers/adapters
    )


def source_onboarding_provider_allowed(provider: str, value: Settings = settings) -> bool:
    """Creation eligibility only; NEVER imply Protect eligibility for Microsoft."""
    if v1_source_provider_allowed(provider, value):
        return True
    return bool(
        value.env == "production"
        and value.v1_provider == GOOGLE_WORKSPACE_DRIVE_V1
        and value.microsoft_shadow_onboarding
        and provider in {"sharepoint", "onedrive"}
    )


def enforce_source_onboarding_provider(provider: str, value: Settings = settings) -> None:
    if not source_onboarding_provider_allowed(provider, value):
        raise V1ProviderScopeError(
            "V1_PROVIDER_NOT_SUPPORTED: Google Drive Protect V1; Microsoft Shadow onboarding requires operator opt-in"
        )


def enforce_v1_source_provider(provider: str, value: Settings = settings) -> None:
    if not v1_source_provider_allowed(provider, value):
        raise V1ProviderScopeError(
            "V1_PROVIDER_NOT_SUPPORTED: production V1 supports only Google Workspace + Google Drive"
        )


def enforce_v1_browser_credential_policy(
    provider: str, credentials: dict[str, object], value: Settings = settings
) -> None:
    """Keep operator OAuth credentials and user tokens off customer APIs.

    The Google OAuth callback is a server-to-server code exchange and does not
    use this function. Development remains permissive for deterministic
    connector fixtures and isolated compatibility tests.
    """
    if value.env != "production":
        return
    if provider == "google-drive" and credentials:
        raise V1ProviderScopeError(
            "V1_BROWSER_CREDENTIALS_NOT_ALLOWED: connect Google Workspace using the server-configured OAuth flow"
        )
    # Microsoft browser inputs are *identifiers only*. Tokens, credentials,
    # OAuth endpoints and other unrecognized fields must come from trusted
    # server-side administrator consent, never be accepted from a request body.
    if provider in {"sharepoint", "onedrive"}:
        allowed = {"tenant_id", "drive_id", "test_root_item_id"}
        if provider == "sharepoint":
            allowed |= {"site_id", "list_id"}
        else:
            allowed.add("owner_object_id")
        if any(key not in allowed or not isinstance(value, str) for key, value in credentials.items()):
            raise V1ProviderScopeError(
                "MICROSOFT_BROWSER_CREDENTIALS_NOT_ALLOWED: provide only approved source identifiers; consent is server-side"
            )


def validate_production_settings(value: Settings = settings) -> None:
    if value.env != "production":
        return
    problems: list[str] = []
    if not value.database_url.startswith("postgresql"):
        problems.append("DATABASE_URL must use PostgreSQL in production, not SQLite")
    if not value.redis_url:
        problems.append("REDIS_URL is required in production")
    if not value.web_origin.startswith("https://"):
        problems.append("WEB_ORIGIN must use HTTPS in production")
    if not value.cors_allowed_origins or any(not origin.startswith("https://") for origin in value.cors_allowed_origins):
        problems.append("CORS_ALLOWED_ORIGINS must contain explicit HTTPS origins in production")
    if any("*" in origin for origin in value.cors_allowed_origins):
        problems.append("CORS_ALLOWED_ORIGINS must not contain wildcard origins in production")
    required_secrets = [
        ("SESSION_HMAC_KEY", value.session_hmac_key),
        ("REPORT_SIGNING_KEY", value.report_signing_key),
    ]
    if value.secret_backend == "local":
        required_secrets.append(("SECRET_ENCRYPTION_KEY", value.secret_encryption_key))
    for name, secret in required_secrets:
        if len(secret) < 32 or any(marker in secret.lower() for marker in ("development", "change-me", "example", "placeholder")):
            problems.append(f"{name} must be a unique secret of at least 32 characters")
    if value.secret_backend == "aws-kms" and not value.aws_kms_key_id:
        problems.append(
            "ACCESSPROOF_AWS_KMS_KEY_ID is required when AWS KMS secret backend is enabled"
        )
    if value.secret_backend not in {"local", "aws-kms"}:
        problems.append("ACCESSPROOF_SECRET_BACKEND must be local or aws-kms")
    if not value.public_app_url.startswith("https://"):
        problems.append("ACCESSPROOF_PUBLIC_APP_URL must use HTTPS in production")
    if not value.api_public_url.startswith("https://"):
        problems.append("API_PUBLIC_URL must use HTTPS in production")
    if value.oidc_redirect_uri and not value.oidc_redirect_uri.startswith("https://"):
        problems.append(
            "ACCESSPROOF_OIDC_REDIRECT_URI must use HTTPS in production when explicitly configured"
        )
    if value.email_delivery_mode != "smtp":
        problems.append("ACCESSPROOF_EMAIL_MODE must be smtp in production")
    if not value.smtp_host:
        problems.append("ACCESSPROOF_SMTP_HOST is required when SMTP delivery is enabled")
    if "*" in value.allowed_hosts or not value.allowed_hosts:
        problems.append("ACCESSPROOF_ALLOWED_HOSTS must contain explicit production hostnames")
    if value.rls_bypass:
        problems.append("ACCESSPROOF_RLS_BYPASS must not be enabled in production")
    if value.v1_provider != GOOGLE_WORKSPACE_DRIVE_V1:
        problems.append(
            "ACCESSPROOF_V1_PROVIDER must be google-workspace-drive in production"
        )
    if problems:
        raise RuntimeError("Unsafe production configuration: " + "; ".join(problems))
