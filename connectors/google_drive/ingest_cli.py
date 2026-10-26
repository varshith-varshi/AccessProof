"""Owner-run Google Drive text ingestion into signed AccessProof retrieval manifests.

Reads a restricted Ed25519 signing key on the customer side, independently
fetches file bytes and version via authenticated Drive API, and writes signed
retrieval metadata to an exclusive, private output file. No API or signing key
is copied to a remote AccessProof service.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import stat
from dataclasses import asdict
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from connectors.google_drive.adapter import GoogleDriveAdapter
from connectors.google_drive.trusted_ingestion import (
    GoogleDriveIngestionSettings, GoogleDriveTrustedIngestion,
)
from packages.rag_sdk.attestation import SourceAttestationSigner
from packages.rag_sdk.ingestion import IngestionError, TrustedSourceIngestor


def _private_signer(key_file: Path, key_id: str) -> SourceAttestationSigner:
    if not key_id or len(key_id) > 128 or any(not (c.isalnum() or c in "-_.") for c in key_id):
        raise IngestionError("Invalid signing key identifier")
    try:
        descriptor = os.open(str(key_file), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
                raise IngestionError("Signing key must be a regular file with mode 0600")
            key_bytes = os.read(descriptor, 33)
            if len(key_bytes) != 32:
                raise IngestionError("Ed25519 raw private key file must contain exactly 32 bytes")
        finally:
            os.close(descriptor)
        return SourceAttestationSigner(key_id=key_id, private_key=Ed25519PrivateKey.from_private_bytes(key_bytes))
    except OSError as exc:
        raise IngestionError("Unable to securely read private signing key") from exc


async def fetch_signed_google_drive_file(
    *, access_token: str, root_folder_id: str, file_id: str,
    tenant_id: str, application_id: str, source_id: str,
    signing_key: Path, key_id: str, max_content_bytes: int = 2_000_000,
) -> tuple[list[dict[str, Any]], str]:
    if not access_token or any(char in access_token for char in "\r\n"):
        raise IngestionError("A provider OAuth access token is required")
    signer = _private_signer(signing_key, key_id)
    settings = GoogleDriveIngestionSettings(
        tenant_id=tenant_id, application_id=application_id, source_id=source_id,
        max_content_bytes=max_content_bytes,
    )
    adapter = GoogleDriveAdapter(access_token=access_token, test_root_folder_id=root_folder_id)
    try:
        await adapter.validate_connection()
        ingester = GoogleDriveTrustedIngestion(adapter, TrustedSourceIngestor(signer), settings)
        resources = await ingester.ingest(file_id)
        public = signer._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return [asdict(resource) for resource in resources], base64.urlsafe_b64encode(public).rstrip(b"=").decode()
    finally:
        await adapter._client.aclose()


def write_private_manifest(path: Path, *, application_id: str,
                           resources: list[dict[str, Any]]) -> None:
    """Never overwrite an existing signed source manifest or follow symlinks."""
    if not path.parent.is_dir():
        raise IngestionError("Manifest destination directory must exist")
    payload = json.dumps({"application_id": application_id, "retrieved_resources": resources},
                         ensure_ascii=True, separators=(",", ":"))
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as result:
                result.write(payload + "\n")
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    except FileExistsError as exc:
        raise IngestionError("Manifest output already exists; choose a new filename") from exc


async def _run(args: argparse.Namespace) -> int:
    token = os.environ.get("ACCESSPROOF_GOOGLE_DRIVE_ACCESS_TOKEN", "")
    resources, public = await fetch_signed_google_drive_file(
        access_token=token, root_folder_id=args.root_folder_id,
        file_id=args.file_id, tenant_id=args.tenant_id,
        application_id=args.application_id, source_id=args.source_id,
        signing_key=args.private_key, key_id=args.key_id,
    )
    write_private_manifest(args.output, application_id=args.application_id, resources=resources)
    print(json.dumps({
        "status": "SIGNED_PROVIDER_FETCH", "chunks": len(resources),
        "key_id": args.key_id, "public_key_base64url": public,
        "output": str(args.output),
        "provider": "google-drive", "format": "accessproof.gateway-manifest/v1",
    }))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch and sign provider-verified Google Drive text.")
    parser.add_argument("--root-folder-id", required=True)
    parser.add_argument("--file-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--application-id", required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        return asyncio.run(_run(args))
    except (IngestionError, ValueError) as exc:
        print("SOURCE_INGESTION_FAILED:", str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
