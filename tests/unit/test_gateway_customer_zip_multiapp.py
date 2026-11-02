"""Regressions for downloaded customer ZIP: discovery and planning must actually run."""
from __future__ import annotations

import importlib.util
import json
import sys
import zipfile
from pathlib import Path

import pytest

from scripts.build_gateway_connector_zipapp import GATEWAY_MODULES, rebuild

REPO = Path(__file__).resolve().parents[2]
ZIPMAIN = REPO / "scripts/gateway_customer_zipapp_main.py"


def test_bundle_contains_all_transitive_multiapp_modules(tmp_path: Path) -> None:
    source = tmp_path / "old.zip"
    target = tmp_path / "new.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("__main__.py", "print('old')")
        archive.writestr("accessproof-gateway-connector/apps/gateway/accessproof_gateway/customer_connect.py", "print('old')")
        archive.writestr("accessproof-gateway-connector/accessproof-gateway-runtime.tar.gz", b"pinned-runtime")
    rebuild(source, target, REPO)
    with zipfile.ZipFile(target) as archive:
        assert archive.read("accessproof-gateway-connector/accessproof-gateway-runtime.tar.gz") == b"pinned-runtime"
        for name in GATEWAY_MODULES:
            member = "accessproof-gateway-connector/apps/gateway/accessproof_gateway/" + name
            assert archive.read(member) == (REPO / "apps/gateway/accessproof_gateway" / name).read_bytes()
        assert b'parser.add_argument("--discover"' in archive.read("__main__.py")
        assert b'parser.add_argument("--plan"' in archive.read("__main__.py")


def _module():
    spec = importlib.util.spec_from_file_location("multiapp_zipmain", ZIPMAIN)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_zip_main_forwards_read_only_discovery_without_pairing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = _module()
    calls = []
    monkeypatch.setattr(module, "verified_connector_from_bundle", lambda: tmp_path / "connect.sh")
    monkeypatch.setattr(module.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(module.subprocess, "call", lambda command, **kwargs: calls.append((command, kwargs)) or 0)
    monkeypatch.setattr(sys, "argv", [str(tmp_path / "installer.zip"), "--discover"])
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 0
    assert calls[0][0][-1] == "--discover"
    assert "--pairing-file" not in calls[0][0]
    assert "--approve-install" not in calls[0][0]


def test_zip_main_forwards_only_explicit_plan_selections(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = _module()
    calls = []
    monkeypatch.setattr(module, "verified_connector_from_bundle", lambda: tmp_path / "connect.sh")
    monkeypatch.setattr(module.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(module.subprocess, "call", lambda command, **kwargs: calls.append(command) or 0)
    monkeypatch.setattr(sys, "argv", [str(tmp_path / "installer.zip"), "--plan", "--select", "host-app-123"])
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 0
    assert calls[0][-3:] == ["--plan", "--select", "host-app-123"]


@pytest.mark.parametrize("flags", [
    ["--plan"], ["--discover", "--select", "host-app-123"],
    ["--discover", "--check"], ["--discover", "--pairing-file", "private.json"],
    ["--plan", "--select", "host-app-123", "--challenge-file", "challenge.json"],
])
def test_zip_main_rejects_invalid_or_mutating_discovery_flags(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, flags: list[str],
) -> None:
    module = _module()
    monkeypatch.setattr(module, "verified_connector_from_bundle",
                        lambda: (_ for _ in ()).throw(AssertionError("must not execute")))
    monkeypatch.setattr(sys, "argv", [str(tmp_path / "installer.zip"), *flags])
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 2


def test_legacy_staged_receipt_without_new_gateway_service_field(tmp_path: Path) -> None:
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from apps.gateway.accessproof_gateway.installer import (
        InstallationSpec, stage_installation, verify_existing_staged_installation,
    )
    key = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    spec = InstallationSpec.parse({
        "tenant_id": "tenant-a", "application_id": "app-a", "rag_service": "rag",
        "guard_url": "http://guard:8080", "model_url": "http://model:8000/v1/chat/completions",
        "trusted_public_keys": {"kid": base64.urlsafe_b64encode(key).decode().rstrip("=")},
    })
    compose = tmp_path / "compose.yml"
    compose.write_text("services:\n  rag:\n    image: example/rag\n")
    output = tmp_path / "private"
    stage_installation(spec, compose, output, {"services": {"rag": {"labels": {
        "com.accessproof.gateway.contract": "accessproof.gateway/v1",
        "com.accessproof.gateway.enforces": "attested-retrieval-and-buffered-output",
        "com.accessproof.gateway.route_env": "ACCESSPROOF_CHAT_URL",
    }}}})
    receipt = output / "installation.json"
    data = json.loads(receipt.read_text())
    data.pop("gateway_service")
    receipt.write_text(json.dumps(data))
    assert verify_existing_staged_installation(spec, compose, output)["state"] == "INSTALLED_UNVERIFIED"


def test_zipmain_does_not_execute_symlinked_installer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = _module()
    original = tmp_path / "original.zip"
    original.write_bytes(b"not a trusted zip")
    symlink = tmp_path / "installer.zip"
    symlink.symlink_to(original)
    monkeypatch.setattr(sys, "argv", [str(symlink), "--discover"])
    with pytest.raises(SystemExit) as exc:
        module.verified_connector_from_bundle()
    assert exc.value.code == 2
