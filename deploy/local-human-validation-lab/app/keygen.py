"""Create a local source-ingester keypair; private PEM never goes to web/LLM."""
from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> None:
    folder = Path("secrets")
    folder.mkdir(mode=0o700, exist_ok=True)
    dest = folder / "source_signing.pem"
    if dest.exists():
        raise SystemExit("Key exists; refusing to overwrite " + str(dest))
    key = Ed25519PrivateKey.generate()
    data = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    print("Created private key at secrets/source_signing.pem")
    print("Public key for Gateway LAB_ATTESTATION_KEY_ID:", base64.b64encode(public).decode())


if __name__ == "__main__":
    main()
