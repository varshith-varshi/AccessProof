"""Offline tests of the isolated web-only production release.

A stub `docker` and `curl` stand in for production, so this never touches AWS,
containers or customer data.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "deploy/ec2-release"
SDK_NAME = "accessproof_rag-0.1.0-py3-none-any.whl"
REVISION = "x8c9d0e1f2a3"
OLD_IMAGE = "accessproof/web-v2:previous"

FAKE_DOCKER = r"""#!/usr/bin/env bash
set -u
echo "docker $*" >> "$STATE/calls"
sub="$1"; shift
if [[ "$sub" == compose ]]; then
  shift 4  # --project-directory <dir> -f <file>
  sub="$1"; shift
  case "$sub" in
    ps) cat "$STATE/cid-$2" ;;
    exec)
      if [[ "$2" == db ]]; then echo "$(cat "$STATE/db-revision")"; exit 0; fi
      [[ ! -e "$STATE/fail-reload" ]] || exit 1 ;;
    up)
      cid="web-$(( $(cat "$STATE/web-generation") + 1 ))"
      echo "${cid#web-}" > "$STATE/web-generation"
      echo "$cid" > "$STATE/cid-web"
      grep '^ACCESSPROOF_WEB_IMAGE=' "$APP_DIR/.env" | cut -d= -f2- > "$STATE/image-$cid" ;;
  esac
  exit 0
fi
case "$sub" in
  inspect)
    if [[ "$1" == -f && "$2" == *Config.Image* ]]; then cat "$STATE/image-$3"
    elif [[ "$3" == worker* ]]; then echo running
    else echo healthy; fi ;;
  cp) cp "$FIXTURE_ZIP" "$2" ;;
  image) exit 1 ;;
  build) [[ ! -e "$STATE/fail-build" ]] ;;
  run)
    case "${@: -1}" in
      *.zip) sha256sum "$FIXTURE_ZIP" ;;
      *) sha256sum "$FIXTURE_SDK" ;;
    esac ;;
esac
"""

FAKE_CURL = r"""#!/usr/bin/env bash
echo "curl $*" >> "$STATE/calls"
case "$*" in
  *downloads*) cat "$STATE/installer-status" ;;
  *) echo 200 ;;
esac
"""


class Rig:
    def __init__(self, tmp: Path) -> None:
        self.home = tmp / "home"
        self.app = self.home / "accessproof"
        self.state = tmp / "state"
        self.stubs = tmp / "stubs"
        self.rel_root = self.home / "accessproof-releases"
        for path in (self.app, self.state, self.stubs, self.rel_root):
            path.mkdir(parents=True)

        self.zip = tmp / "connector.zip"
        with zipfile.ZipFile(self.zip, "w") as bundle:
            bundle.writestr("__main__.py", "print('synthetic')\n")
            bundle.writestr("accessproof-gateway-connector/accessproof-gateway-runtime.tar.gz", b"synthetic")
        self.sdk = tmp / SDK_NAME
        self.sdk.write_bytes(b"synthetic sdk")

        (self.app / ".env").write_text(f"KEEP=1\nACCESSPROOF_WEB_IMAGE={OLD_IMAGE}\n")
        (self.app / "docker-compose.ec2.yml").write_text("services: {}\n")
        for service in ("db", "redis", "api", "worker", "nginx"):
            (self.state / f"cid-{service}").write_text(f"{service}-original\n")
        (self.state / "cid-web").write_text("web-0\n")
        (self.state / "image-web-0").write_text(OLD_IMAGE + "\n")
        (self.state / "web-generation").write_text("0\n")
        (self.state / "db-revision").write_text(REVISION + "\n")
        (self.state / "installer-status").write_text("307\n")
        (self.state / "calls").write_text("")
        for name, body in (("docker", FAKE_DOCKER), ("curl", FAKE_CURL)):
            stub = self.stubs / name
            stub.write_text(body)
            stub.chmod(0o755)

    def patched(self, name: str) -> str:
        text = (SCRIPTS / name).read_text().replace("/home/ubuntu", str(self.home))
        lines = []
        for line in text.splitlines():
            if line.startswith("GATEWAY_SHA="):
                line = f"GATEWAY_SHA='{hashlib.sha256(self.zip.read_bytes()).hexdigest()}'"
            elif line.startswith("SDK_SHA="):
                line = f"SDK_SHA='{hashlib.sha256(self.sdk.read_bytes()).hexdigest()}'"
            lines.append(line)
        return "\n".join(lines) + "\n"

    def artifact(self, rid: str) -> tuple[Path, str, Path]:
        src = self.home / "artifact-src"
        scripts = src / "deploy/ec2-release"
        downloads = src / "web-v2/public/downloads"
        scripts.mkdir(parents=True)
        downloads.mkdir(parents=True)
        (src / "RELEASE_COMMIT").write_text("a" * 40)
        (src / "web-v2/Dockerfile").write_text("FROM scratch\n")
        shutil.copy(self.sdk, downloads / SDK_NAME)
        for name in ("deploy_on_ec2.sh", "deploy_web_only_on_ec2.sh"):
            (scripts / name).write_text(self.patched(name))
        rel = self.rel_root / rid
        rel.mkdir()
        tar = rel / "artifact.tar"
        with tarfile.open(tar, "w") as archive:
            for child in src.iterdir():
                archive.add(child, arcname=child.name)
        entry = rel / "deploy_on_ec2.sh"
        entry.write_text(self.patched("deploy_on_ec2.sh"))
        return tar, hashlib.sha256(tar.read_bytes()).hexdigest(), entry

    def run(self, rid: str = "web-r39-onboarding-168458867ee3", *, expected: str = REVISION):
        tar, sha, entry = self.artifact(rid)
        env = {
            **os.environ,
            "PATH": f"{self.stubs}:{os.environ['PATH']}",
            "STATE": str(self.state),
            "APP_DIR": str(self.app),
            "FIXTURE_ZIP": str(self.zip),
            "FIXTURE_SDK": str(self.sdk),
            "EXPECTED_DB_REVISION": expected,
            "PUBLIC_CHECKS": "1",
        }
        return subprocess.run(
            ["bash", str(entry), rid, str(tar), sha],
            text=True, capture_output=True, timeout=60, env=env,
        )

    @property
    def calls(self) -> str:
        return (self.state / "calls").read_text()

    def web_image(self) -> str:
        cid = (self.state / "cid-web").read_text().strip()
        return (self.state / f"image-{cid}").read_text().strip()

    def untouched(self) -> bool:
        return all(
            (self.state / f"cid-{service}").read_text().strip() == f"{service}-original"
            for service in ("db", "redis", "api", "worker", "nginx")
        )


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    return Rig(tmp_path)


def test_web_release_replaces_only_web_and_reloads_nginx(rig: Rig) -> None:
    result = rig.run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "WEB-ONLY RELEASE VERIFIED" in result.stdout
    assert rig.web_image() == "accessproof/web-v2:web-r39-onboarding-168458867ee3"
    assert rig.untouched()
    assert "nginx -s reload" in rig.calls
    assert "--force-recreate web" in rig.calls
    assert "--force-recreate api" not in rig.calls
    assert "--force-recreate worker" not in rig.calls
    assert "apps/api/Dockerfile" not in rig.calls
    assert "pg_dump" not in rig.calls
    assert "alembic upgrade" not in rig.calls


def test_web_build_yields_resources_to_live_production_services(rig: Rig) -> None:
    result = rig.run()
    assert result.returncode == 0, result.stdout + result.stderr
    script = (SCRIPTS / "deploy_web_only_on_ec2.sh").read_text()
    assert 'timeout --signal=TERM --kill-after=30s 20m' in script
    assert 'nice -n 10 ionice -c2 -n7 docker build' in script
    assert "docker build" in rig.calls


def test_installer_probe_uses_head_and_get(rig: Rig) -> None:
    assert rig.run().returncode == 0
    probes = [line for line in rig.calls.splitlines() if line.startswith("curl") and "downloads" in line]
    assert any(" -I " in line for line in probes)
    assert any(" -r 0-0 " in line for line in probes)


def test_open_installer_rolls_back_to_previous_image(rig: Rig) -> None:
    (rig.state / "installer-status").write_text("200\n")
    result = rig.run()
    assert result.returncode != 0
    assert "WEB ROLLBACK VERIFIED" in result.stdout
    assert rig.web_image() == OLD_IMAGE
    assert f"ACCESSPROOF_WEB_IMAGE={OLD_IMAGE}" in (rig.app / ".env").read_text()
    assert rig.calls.count("nginx -s reload") == 2
    assert rig.untouched()


def test_failed_nginx_reload_rolls_back_and_flags_operator(rig: Rig) -> None:
    (rig.state / "fail-reload").write_text("")
    result = rig.run()
    assert result.returncode != 0
    assert "CRITICAL: WEB ROLLBACK NOT VERIFIED" in result.stderr
    assert f"ACCESSPROOF_WEB_IMAGE={OLD_IMAGE}" in (rig.app / ".env").read_text()


def test_failed_build_leaves_production_untouched(rig: Rig) -> None:
    (rig.state / "fail-build").write_text("")
    result = rig.run()
    assert result.returncode != 0
    assert "--force-recreate" not in rig.calls
    assert rig.web_image() == OLD_IMAGE


def test_database_drift_refuses_before_any_work(rig: Rig) -> None:
    result = rig.run(expected="a1b2c3d4e5f6")
    assert result.returncode != 0
    assert "docker build" not in rig.calls
    assert "--force-recreate" not in rig.calls


def test_label_without_web_prefix_keeps_full_release_path(rig: Rig) -> None:
    result = rig.run("r40-fullrelease-168458867ee3", expected="a1b2c3d4e5f6")
    assert result.returncode != 0
    assert "unexpected DB revision" in result.stdout
    assert "WEB-ONLY" not in result.stdout


@pytest.mark.parametrize("script", ["deploy_on_ec2.sh", "deploy_web_only_on_ec2.sh"])
def test_scripts_are_syntactically_valid(script: str) -> None:
    assert subprocess.run(["bash", "-n", str(SCRIPTS / script)], check=False).returncode == 0


def test_release_document_accepts_session_signed_artifact_url() -> None:
    document = json.loads((ROOT / "deploy/deployer/ssm/AccessProof-Deployer-ProductionRelease.json").read_text())
    pattern = document["parameters"]["artifactUrlB64"]["allowedPattern"]
    # A Roles Anywhere session token makes a presigned URL about 2,300 base64 characters.
    assert re.fullmatch(pattern, "A" * 2400)
