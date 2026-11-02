"""Rebuild the customer installer with the verified runtime unchanged.

Replaces ONLY Python entrypoint and customer pairing implementation, preserving
the bundled, SHA-256-pinned Gateway container runtime. Never bundles credentials.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import shutil
import tempfile
import zipfile
from pathlib import Path

ENTRYPOINT = "__main__.py"
CONNECTOR = "accessproof-gateway-connector/apps/gateway/accessproof_gateway/customer_connect.py"
DISCOVERY = "accessproof-gateway-connector/apps/gateway/accessproof_gateway/application_discovery.py"
RUNTIME = "accessproof-gateway-connector/accessproof-gateway-runtime.tar.gz"


def sha256(archive: zipfile.ZipFile, name: str) -> str:
    with archive.open(name) as payload:
        digest = hashlib.sha256()
        for data in iter(lambda: payload.read(1024 * 1024), b""):
            digest.update(data)
    return digest.hexdigest()


def rebuild(source_zip: Path, target_zip: Path, repo: Path) -> None:
    if source_zip.resolve() == target_zip.resolve():
        raise ValueError("Use a new output archive to preserve the old version for rollback.")
    replacements = {
        ENTRYPOINT: (repo / "scripts/gateway_customer_zipapp_main.py").read_bytes(),
        CONNECTOR: (repo / "apps/gateway/accessproof_gateway/customer_connect.py").read_bytes(),
        DISCOVERY: (repo / "apps/gateway/accessproof_gateway/application_discovery.py").read_bytes(),
    }
    target_zip.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target_zip.parent) as tmp:
        pending = Path(tmp) / "gateway-patched.zip"
        with zipfile.ZipFile(source_zip, "r") as old, zipfile.ZipFile(
            pending, "w", allowZip64=True
        ) as updated:
            names = old.namelist()
            required = {ENTRYPOINT, CONNECTOR}
            if len(names) != len(set(names)) or not required.issubset(names) or RUNTIME not in names:
                raise ValueError("Unsupported or incomplete Gateway installer archive.")
            runtime_digest = sha256(old, RUNTIME)
            for item in old.infolist():
                fresh = copy.copy(item)
                with updated.open(fresh, "w") as output:
                    if item.filename in replacements:
                        output.write(replacements[item.filename])
                    else:
                        with old.open(item.filename) as source:
                            shutil.copyfileobj(source, output, 1024 * 1024)
            if DISCOVERY not in names:
                updated.writestr(DISCOVERY, replacements[DISCOVERY])
        with zipfile.ZipFile(pending) as verified:
            assert verified.testzip() is None
            assert set(verified.namelist()) == set(names) | {DISCOVERY}
            assert sha256(verified, RUNTIME) == runtime_digest
            for filename, expected in replacements.items():
                if verified.read(filename) != expected:
                    raise ValueError("Installer update did not match reviewed source.")
            if b"run_doctor" not in replacements[ENTRYPOINT] or b"Automatic cloud security preflight" not in replacements[CONNECTOR]:
                raise ValueError("New installer does not contain automatic verification.")
        pending.replace(target_zip)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    rebuild(args.source, args.output, args.repo)
    with args.output.open("rb") as output:
        digest = hashlib.file_digest(output, "sha256").hexdigest()
    print("Updated installer:", args.output)
    print("SHA-256:", digest)


if __name__ == "__main__":
    main()
