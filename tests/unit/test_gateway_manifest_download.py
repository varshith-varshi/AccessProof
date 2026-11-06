"""Downloaded customer Gateway manifest is an export, not certification."""
import json
import os
from pathlib import Path

import pytest

from apps.gateway.accessproof_gateway.customer_connect import (
    ConnectError, publish_installation_manifest,
)


def _manifest(where: Path, *, app: str = "accessproof-human-validation-rag", route: str = "b") -> Path:
    path = where / "installation.json"
    path.write_text(json.dumps({
        "application_id": app,
        "reference_contract": "accessproof.gateway/v1",
        "deployment_sha256": "a" * 64,
        "route_sha256": route * 64,
        "state": "installed",
    }))
    path.chmod(0o600)
    return path


def test_creates_private_download_and_preserves_original(tmp_path):
    source = _manifest(tmp_path)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    original = source.read_bytes()
    result = publish_installation_manifest(source, "accessproof-human-validation-rag", downloads=downloads)
    assert result == downloads / "accessproof-human-validation-rag-installation.json"
    assert result.read_bytes() == original == source.read_bytes()
    assert result.stat().st_mode & 0o777 == 0o600
    assert publish_installation_manifest(source, "accessproof-human-validation-rag", downloads=downloads) == result
    assert sorted(downloads.iterdir()) == [result]


def test_changed_manifest_keeps_previous_file(tmp_path):
    source = _manifest(tmp_path)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    first = publish_installation_manifest(source, "accessproof-human-validation-rag", downloads=downloads)
    old = first.read_bytes()
    _manifest(tmp_path, route="c")
    second = publish_installation_manifest(source, "accessproof-human-validation-rag", downloads=downloads)
    assert first != second
    assert second.name == "accessproof-human-validation-rag-installation-2.json"
    assert first.read_bytes() == old
    assert second.read_bytes() != old


def test_symlink_destination_is_skipped_without_following(tmp_path):
    source = _manifest(tmp_path)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    victim = tmp_path / "do-not-touch"
    victim.write_text("leave")
    (downloads / "accessproof-human-validation-rag-installation.json").symlink_to(victim)
    exported = publish_installation_manifest(source, "accessproof-human-validation-rag", downloads=downloads)
    assert exported.name.endswith("-2.json")
    assert victim.read_text() == "leave"


@pytest.mark.parametrize("app", ["../bad", "a/b", "", "--unsafe", "x" * 130])
def test_rejects_unsafe_app_names(tmp_path, app):
    source = _manifest(tmp_path)
    with pytest.raises(ConnectError, match="unsafe"):
        publish_installation_manifest(source, app, downloads=tmp_path)


def test_missing_download_directory_does_not_create_one(tmp_path):
    source = _manifest(tmp_path)
    with pytest.raises(ConnectError, match="Downloads directory"):
        publish_installation_manifest(source, "app", downloads=tmp_path / "absent")


def test_rejects_secret_fields(tmp_path):
    source = _manifest(tmp_path)
    data = json.loads(source.read_text())
    data["pairing_token"] = "should-not-export"
    source.write_text(json.dumps(data))
    with pytest.raises(ConnectError, match="not safe"):
        publish_installation_manifest(source, "accessproof-human-validation-rag", downloads=tmp_path)
