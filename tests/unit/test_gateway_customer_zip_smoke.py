"""Regression tests for the offline published customer download smoke check."""
from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from scripts.smoke_gateway_customer_zip import CHALLENGE_CLI, MANIFEST, REQUIRED, RUNTIME, verify


def _zip(tmp_path: Path, *, bad_runtime: bool = False, old_challenge: bool = False) -> tuple[Path, str]:
    target = tmp_path / "customer.zip"
    archive_digest = hashlib.sha256(b"runtime").hexdigest()
    with zipfile.ZipFile(target, "w") as archive:
        for filename in REQUIRED:
            if filename == RUNTIME:
                payload = b"runtime"
            elif filename == MANIFEST:
                payload = json.dumps({"schema": "accessproof.gateway_runtime/v1",
                                      "archive_sha256": "0" * 64 if bad_runtime else archive_digest,
                                      "image": "gateway:fixture"}).encode()
            elif filename == CHALLENGE_CLI:
                payload = b"# no fix" if old_challenge else b"def merge_issued_challenge(): pass"
            else:
                payload = b"fixture"
            archive.writestr(filename, payload)
    return target, hashlib.sha256(target.read_bytes()).hexdigest()


def test_published_zip_validates_without_executing_install(tmp_path: Path) -> None:
    path, sha = _zip(tmp_path)
    result = verify(path, sha)
    assert result["result"] == "SMOKE_PASS"
    assert result["live_pairing"] == "NOT_RUN"


def test_published_zip_refuses_wrong_artifact(tmp_path: Path) -> None:
    path, _ = _zip(tmp_path)
    with pytest.raises(ValueError, match="approved SHA-256"):
        verify(path, "0" * 64)


def test_published_zip_refuses_unverified_runtime(tmp_path: Path) -> None:
    path, sha = _zip(tmp_path, bad_runtime=True)
    with pytest.raises(ValueError, match="Runtime digest"):
        verify(path, sha)


def test_published_zip_refuses_old_challenge_cli(tmp_path: Path) -> None:
    path, sha = _zip(tmp_path, old_challenge=True)
    with pytest.raises(ValueError, match="route-challenge fix"):
        verify(path, sha)
