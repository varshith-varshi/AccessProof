"""Fail locally if any reviewed production installer digest is inconsistent.

This is a release preflight, not production certification. The installer
runtime remains hash pinned and is never modified by this script.
"""
from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PINS = {
    "deploy/deployer/ship_production.sh": r"^GATEWAY_ZIP_SHA=([0-9a-f]{64})$",
    "deploy/ec2-release/deploy_web_only_on_ec2.sh": r"^GATEWAY_SHA='([0-9a-f]{64})'$",
    "deploy/ec2-release/deploy_on_ec2.sh": r'^EXPECTED_GATEWAY_INSTALLER_SHA256="([0-9a-f]{64})"$',
}


def verify(archive: Path, root: Path = REPO) -> str:
    """Check all immutable release pins and the local ZIP's actual SHA-256."""
    pins = {}
    for relative, pattern in PINS.items():
        matches = re.findall(pattern, (root / relative).read_text(), flags=re.M)
        if len(matches) != 1:
            raise ValueError(f"Missing or duplicated installer pin in {relative}")
        pins[relative] = matches[0]
    if len(set(pins.values())) != 1:
        raise ValueError(f"Installer pin mismatch across release scripts: {pins}")
    if not archive.is_file() or archive.is_symlink():
        raise ValueError("Pinned installer file is missing or unsafe")
    with archive.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    expected = next(iter(pins.values()))
    if actual != expected:
        raise ValueError(f"Installer file hash does not match reviewed release pin: {actual}")
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip", required=True, type=Path)
    args = parser.parse_args()
    try:
        print("RELEASE_INSTALLER_PINS_VERIFIED", verify(args.zip))
        return 0
    except (OSError, ValueError) as exc:
        parser.exit(2, f"RELEASE_INSTALLER_PINS_MISMATCH: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
