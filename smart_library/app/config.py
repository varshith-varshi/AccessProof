from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    """Runtime settings. All values can be overridden with SLMS_* environment variables."""

    db_path: str = field(default_factory=lambda: os.getenv("SLMS_DB_PATH", "smart_library.db"))
    # Secret used to sign member tokens and search-result attestations.
    secret_key: str = field(default_factory=lambda: os.getenv("SLMS_SECRET_KEY", "dev-only-change-me"))
    token_ttl_seconds: int = field(default_factory=lambda: int(os.getenv("SLMS_TOKEN_TTL", "3600")))
    # Guard refuses to decide if its installed policy is older than this (fail closed).
    max_policy_staleness_seconds: int = field(
        default_factory=lambda: int(os.getenv("SLMS_MAX_POLICY_STALENESS", "600"))
    )
    # Background reconciliation cadences (intervals, not a revocation SLA).
    acl_sync_interval_seconds: int = field(default_factory=lambda: int(os.getenv("SLMS_ACL_SYNC", "300")))
    loan_days: int = field(default_factory=lambda: int(os.getenv("SLMS_LOAN_DAYS", "14")))
    max_active_loans: int = field(default_factory=lambda: int(os.getenv("SLMS_MAX_LOANS", "5")))
    fine_per_day: float = field(default_factory=lambda: float(os.getenv("SLMS_FINE_PER_DAY", "0.50")))
    attestation_ttl_seconds: int = field(default_factory=lambda: int(os.getenv("SLMS_ATTESTATION_TTL", "900")))
    # Loads the extended demo catalogue and demo circulation history (safe to rerun).
    demo_data: bool = field(default_factory=lambda: os.getenv("SLMS_DEMO_DATA", "1") == "1")
    # A loan is flagged "due soon" when it is due within this many days.
    due_soon_days: int = field(default_factory=lambda: int(os.getenv("SLMS_DUE_SOON_DAYS", "3")))
