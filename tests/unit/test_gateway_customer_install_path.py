"""The customer ZIP has no Dockerfile, so a fresh install must use its runtime."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from apps.gateway.accessproof_gateway import installer, integration_wizard

ROOT = Path(__file__).resolve().parents[2]


class Docker:
    def __init__(self, image_exists: bool) -> None:
        self.image_exists = image_exists
        self.calls: list[list[str]] = []

    def run(self, args, **_kwargs):
        self.calls.append(list(args))
        rc = 0
        out = ""
        if args[:3] == ["docker", "image", "inspect"]:
            rc = 0 if self.image_exists else 1
        if "config" in args:
            out = "{}"
        return SimpleNamespace(returncode=rc, stdout=out, stderr="")


@pytest.mark.parametrize(("image_exists", "builds"), [(True, False), (False, True)])
def test_build_only_happens_without_a_verified_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, image_exists: bool, builds: bool,
) -> None:
    docker = Docker(image_exists)
    compose = tmp_path / "compose.yml"
    compose.write_text("services: {}\n")
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    monkeypatch.setattr(installer.subprocess, "run", docker.run)
    monkeypatch.setattr(installer.InstallationSpec, "parse", lambda _value: SimpleNamespace(
        gateway_service="accessproof-gateway", gateway_image="gateway:v4", listen_port=8090,
    ))
    monkeypatch.setattr(installer, "verify_existing_staged_installation", lambda *_args: {
        "compose": str(compose), "override": "override.json",
    })
    monkeypatch.setattr(installer, "wait_for_gateway_liveness", lambda _port: None)
    monkeypatch.setattr(sys, "argv", [
        "installer", "--spec", str(spec), "--compose", str(compose),
        "--output", str(tmp_path / "out"), "--apply-staged",
    ])
    assert installer.main() == 0
    assert any(call[:2] == ["docker", "build"] for call in docker.calls) is builds


def test_install_failure_reaches_the_customer_as_a_readable_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(integration_wizard.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(
        returncode=2, stdout="INSTALLATION_FAILED: port is already in use\n", stderr="",
    ))
    with pytest.raises(integration_wizard.IntegrationWizardError, match="port is already in use"):
        integration_wizard._run_installer_apply(Path("s"), Path("c"), Path("o"))


def test_zip_builder_ships_the_customer_install_modules() -> None:
    source = (ROOT / "scripts/build_gateway_connector_zipapp.py").read_text()
    modules = re.search(r"GATEWAY_MODULES = \((.*?)\)", source, re.S).group(1)
    for name in ("installer.py", "integration_wizard.py", "existing_gateway.py", "challenge_cli.py"):
        assert name in modules
    assert subprocess.run(["bash", "-n", str(ROOT / "deploy/ec2-release/deploy_web_only_on_ec2.sh")]).returncode == 0
