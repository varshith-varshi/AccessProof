"""Read-only, repeatable smoke check of a published customer Gateway ZIP.

Does not connect to a tenant, run Docker, pair a Gateway, or certify Protect.
Use the separate synthetic install fixture for those integration checks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

PREFIX = "accessproof-gateway-connector/"
RUNTIME = PREFIX + "accessproof-gateway-runtime.tar.gz"
MANIFEST = PREFIX + "runtime-release.json"
CHALLENGE_CLI = PREFIX + "apps/gateway/accessproof_gateway/challenge_cli.py"
REQUIRED = {
    "__main__.py",
    PREFIX + "apps/gateway/accessproof_gateway/installer.py",
    PREFIX + "apps/gateway/accessproof_gateway/integration_wizard.py",
    PREFIX + "apps/gateway/accessproof_gateway/customer_connect.py",
    CHALLENGE_CLI, RUNTIME, MANIFEST,
}


def digest_stream(stream) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def verify(path: Path, expected_sha: str, *, current_source: Path | None = None) -> dict:
    if not path.is_file() or path.is_symlink():
        raise ValueError("Installer must be an existing regular file")
    if len(expected_sha) != 64 or any(c not in "0123456789abcdef" for c in expected_sha):
        raise ValueError("Expected SHA-256 must be a complete lowercase digest")
    with path.open("rb") as stream:
        actual = digest_stream(stream)
    if actual != expected_sha:
        raise ValueError("Installer ZIP does not match the approved SHA-256")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or not REQUIRED.issubset(names):
            raise ValueError("Required installer files missing or duplicated")
        for member in archive.infolist():
            name = member.filename
            if name.startswith("/") or "\\" in name or ".." in Path(name).parts:
                raise ValueError("Unsafe path in installer ZIP")
        if archive.testzip() is not None:
            raise ValueError("Installer ZIP CRC verification failed")
        manifest = json.loads(archive.read(MANIFEST))
        if manifest.get("schema") != "accessproof.gateway_runtime/v1":
            raise ValueError("Unsupported Gateway runtime manifest schema")
        with archive.open(RUNTIME) as stream:
            runtime_sha = digest_stream(stream)
        if runtime_sha != manifest.get("archive_sha256"):
            raise ValueError("Runtime digest differs from its manifest")
        if b"merge_issued_challenge" not in archive.read(CHALLENGE_CLI):
            raise ValueError("Gateway ZIP lacks the reviewed route-challenge fix")
        if current_source is not None and archive.read(CHALLENGE_CLI) != current_source.read_bytes():
            raise ValueError("Packaged challenge CLI differs from reviewed source")
        return {"result": "SMOKE_PASS", "installer_sha256": actual,
                "runtime_sha256": runtime_sha, "runtime_image": manifest.get("image"),
                "customer_install": "NOT_RUN", "live_pairing": "NOT_RUN",
                "route_certification": "NOT_RUN"}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--zip", required=True, type=Path)
    p.add_argument("--expected-sha256", required=True)
    p.add_argument("--current-source", type=Path,
                   help="Require packaged challenge_cli.py to equal the reviewed repo file")
    args = p.parse_args()
    try:
        print(json.dumps(verify(args.zip, args.expected_sha256, current_source=args.current_source), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print("SMOKE_FAIL:", str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
