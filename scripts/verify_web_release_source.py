"""Fail closed if a future frontend release would remove the live onboarding route.

The deployed Next.js bundle contains /onboarding, but web-v2 source must
also contain the route before any rebuild/release is considered reproducible.
This is deliberately a source-of-truth release check, not a production cert.
"""
from __future__ import annotations

import argparse
from pathlib import Path


def verify_frontend_route_source(root: Path) -> list[str]:
    source = root / "web-v2" / "app" / "onboarding" / "page.tsx"
    failures = []
    if not source.is_file() or source.is_symlink():
        failures.append(
            "MISSING_CANONICAL_ONBOARDING_PAGE: web-v2/app/onboarding/page.tsx "
            "does not exist. A clean web-v2 build could drop the live "
            "/onboarding route. Recover and test the TypeScript source before "
            "a new web deployment."
        )
    elif source.stat().st_size < 200:
        failures.append(
            "INCOMPLETE_CANONICAL_ONBOARDING_PAGE: web-v2/app/onboarding/page.tsx "
            "is too small to represent the supported three-step customer flow."
        )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Check release source parity for AccessProof")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    failures = verify_frontend_route_source(args.root.expanduser().resolve())
    if failures:
        for failure in failures:
            print("RELEASE BLOCKED:", failure)
        return 2
    print("Onboarding page source exists; continue with Next.js build and browser E2E checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
