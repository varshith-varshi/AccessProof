"""Export only the reviewed AWS KMS Ed25519 certifier PUBLIC key for Owner trust pinning.

No certificate issuance, IAM write, signer key creation or production change.
The operator must independently approve adding the output key to the API trust
set. Invoke with AWS_PROFILE=accessproof-certifier and --kms-key-arn <full ARN>.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
from cryptography.hazmat.primitives import serialization
from packages.crypto.aws_kms_signer import KmsEd25519Signer, KmsSignerError

_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,32}$")


def export(arn: str, key_id: str) -> dict[str, str]:
    if not _KEY_ID.fullmatch(key_id) or key_id in ("certifier-1", "ap-certifier-2026-11"):
        raise KmsSignerError("KMS_DISTINCT_KEY_ID_REQUIRED")
    key = KmsEd25519Signer(arn).public_key()
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {key_id: base64.urlsafe_b64encode(raw).decode().rstrip("=")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kms-key-arn", required=True)
    parser.add_argument("--key-id", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(export(args.kms_key_arn, args.key_id)))
    except KmsSignerError as exc:
        parser.exit(2, f"KMS_PUBLIC_KEY_EXPORT_REFUSED:{exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
