from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from connectors.google_drive.ingest_cli import _private_signer, write_private_manifest
from packages.rag_core.ingestion import IngestionError


def test_provider_signer_requires_private_file_mode_and_never_logs_key(tmp_path: Path) -> None:
    path = tmp_path / "signer.key"
    private = Ed25519PrivateKey.generate()
    path.write_bytes(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    path.chmod(0o600)
    signer = _private_signer(path, "key-1")
    assert signer.key_id == "key-1"
    path.chmod(0o644)
    with pytest.raises(IngestionError, match="mode 0600"):
        _private_signer(path, "key-1")


def test_provider_signer_rejects_key_symlink(tmp_path: Path) -> None:
    real = tmp_path / "secret.key"
    real.write_bytes(b"A" * 32)
    real.chmod(0o600)
    link = tmp_path / "link.key"
    link.symlink_to(real)
    with pytest.raises(IngestionError):
        _private_signer(link, "key-1")


def test_ingestion_output_is_private_and_non_overwriting(tmp_path: Path) -> None:
    output = tmp_path / "provider.manifest.json"
    write_private_manifest(output, application_id="customer-rag", resources=[
        {"source_id": "drive", "resource_id": "doc", "content": "sensitive text"},
    ])
    assert output.stat().st_mode & 0o777 == 0o600
    assert "sensitive text" in output.read_text()
    with pytest.raises(IngestionError, match="already exists"):
        write_private_manifest(output, application_id="customer-rag", resources=[])
    assert "sensitive text" in output.read_text()


def test_ingestion_output_does_not_follow_symlinks(tmp_path: Path) -> None:
    original = tmp_path / "untouchable"
    original.write_text("preserve")
    link = tmp_path / "manifest"
    link.symlink_to(original)
    with pytest.raises(IngestionError):
        write_private_manifest(link, application_id="x", resources=[])
    assert original.read_text() == "preserve"
