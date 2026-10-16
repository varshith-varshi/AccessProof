"""Safe preflight check for an AccessProof production environment.

This intentionally reports only setting names and pass/fail state; it never
prints a value, URL query, or credential.
"""
from __future__ import annotations

from apps.api.accessproof_api.config import settings, validate_production_settings


def main() -> int:
    if settings.env != "production":
        print("FAIL ACCESSPROOF_ENV must be production")
        return 1
    try:
        validate_production_settings(settings)
    except RuntimeError as exc:
        print("FAIL production configuration")
        for problem in str(exc).removeprefix("Unsafe production configuration: ").split("; "):
            print(f"FAIL {problem}")
        return 1
    checks = (
        "database configured",
        "Redis configured",
        "HTTPS public URLs configured",
        "restricted CORS configured",
        "SMTP configured",
        "required secrets configured",
        "explicit allowed hosts configured",
        "RLS bypass disabled",
    )
    for check in checks:
        print(f"PASS {check}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
