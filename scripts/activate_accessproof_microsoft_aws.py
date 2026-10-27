#!/usr/bin/env python3
"""Activate one operator-owned AccessProof Entra secret after approved file transfer.

Runs ON EC2 only, where the operator has already placed the 0600 credential
JSON. Never prints its value and never sends it over a network.
Do not run until the authorized file transfer has completed.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

EXPECTED_CLIENT_ID = "b8424d54-5428-4d35-ae2c-639de7e512a9"
CREDENTIAL = Path("/home/ubuntu/.config/accessproof/entra-client-secret.json")
ENV = Path("/home/ubuntu/accessproof/.env")
BACKUP = Path("/home/ubuntu/accessproof/backups/multitenant-20261027/deployment.before-microsoft-secret.env")


def main() -> None:
    if CREDENTIAL.is_symlink() or not CREDENTIAL.is_file():
        raise SystemExit("Microsoft operator credential file not installed")
    meta = CREDENTIAL.stat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
        raise SystemExit("Credential must be owner-owned regular file with mode 0600")
    credential = json.loads(CREDENTIAL.read_text())
    if credential.get("client_id") != EXPECTED_CLIENT_ID:
        raise SystemExit("Client ID does not match the registered AccessProof application")
    secret = credential.get("client_secret")
    if not isinstance(secret, str) or len(secret) < 20:
        raise SystemExit("Credential value is missing or too short")
    # .env single-quoted values are literal in Compose; reject characters that
    # cannot be encoded safely without a dedicated secret-provider adapter.
    if not secret.isascii() or any(x in secret for x in ["'", "\n", "\r", "\x00"]):
        raise SystemExit("Credential requires a dedicated secret-manager encoding")
    expiry = credential.get("expires_at")
    if expiry:
        deadline = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        if deadline <= datetime.now(timezone.utc) + timedelta(days=3):
            raise SystemExit("Microsoft secret expires too soon: rotate before deployment")
    if ENV.is_symlink() or not ENV.is_file():
        raise SystemExit("Deployment environment file is missing or a symlink")
    if ENV.stat().st_mode & 0o077:
        raise SystemExit("Deployment environment must have owner-only permissions")
    lines = ENV.read_text().splitlines()
    updated = []
    for line in lines:
        if line.startswith("ACCESSPROOF_MICROSOFT_CLIENT_ID="):
            continue
        if line.startswith("ACCESSPROOF_MICROSOFT_CLIENT_SECRET="):
            continue
        updated.append(line)
    updated.extend([
        "ACCESSPROOF_MICROSOFT_CLIENT_ID=" + EXPECTED_CLIENT_ID,
        "ACCESSPROOF_MICROSOFT_CLIENT_SECRET='" + secret + "'",
    ])
    BACKUP.parent.mkdir(parents=True, exist_ok=True)
    if not BACKUP.exists():
        shutil.copy2(ENV, BACKUP)
        BACKUP.chmod(0o600)
    fd, name = tempfile.mkstemp(prefix=".env.entra.", dir=str(ENV.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write("\n".join(updated) + "\n")
        os.replace(name, ENV)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    print("MICROSOFT_OPERATOR_SECRET_INSTALLED_SAFELY")
    print("Run Compose config --quiet and restart only the API and worker.")


if __name__ == "__main__":
    main()
