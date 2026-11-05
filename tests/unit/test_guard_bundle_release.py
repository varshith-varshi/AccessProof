"""Offline tests of the Guard bundle release. Never touches AWS or production."""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from tests.unit.test_web_only_release import SCRIPTS, Rig

RID = "guard-r41-installer-168458867ee3"
OLD_API = "accessproof/api:previous"
NEW_API = f"accessproof/api:{RID}"
BUNDLE = "accessproof-guard-0.1.6.tar.gz"

FAKE_DOCKER = r"""#!/usr/bin/env bash
set -u
echo "docker $*" >> "$STATE/calls"
sub="$1"; shift
if [[ "$sub" == compose ]]; then
  shift 4
  sub="$1"; shift
  case "$sub" in
    ps) cat "$STATE/cid-$2" ;;
    exec)
      case "$2" in
        db) cat "$STATE/db-revision" ;;
        nginx) [[ ! -e "$STATE/fail-reload" ]] || exit 1 ;;
        api) [[ ! -e "$STATE/no-version" ]] && grep '^ACCESSPROOF_GUARD_RELEASE_VERSION=' "$APP_DIR/.env" | cut -d= -f2- ;;
      esac ;;
    up)
      generation=$(( $(cat "$STATE/api-generation") + 1 ))
      echo "$generation" > "$STATE/api-generation"
      echo "api-$generation" > "$STATE/cid-api"
      grep '^ACCESSPROOF_API_IMAGE=' "$APP_DIR/.env" | cut -d= -f2- > "$STATE/image-api-$generation" ;;
  esac
  exit 0
fi
case "$sub" in
  inspect)
    if [[ "$2" == *Config.Image* ]]; then cat "$STATE/image-$3"
    elif [[ "$3" == worker* ]]; then echo running
    else echo healthy; fi ;;
  image)
    [[ "${@: -1}" != accessproof/api:previous ]] || { [[ ! -e "$STATE/no-previous-image" ]]; exit; }
    exit 1 ;;
  create) echo stage ;;
  cp) cp "$1" "$STATE/copied" ;;
  run) sha256sum "$STATE/copied" ;;
esac
"""


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    rig = Rig(tmp_path)
    (rig.stubs / "docker").write_text(FAKE_DOCKER)
    (rig.app / ".env").write_text(f"ACCESSPROOF_API_IMAGE={OLD_API}\nACCESSPROOF_GUARD_RELEASE_VERSION=0.1.5\n")
    (rig.state / "cid-api").write_text("api-0\n")
    (rig.state / "image-api-0").write_text(OLD_API + "\n")
    (rig.state / "api-generation").write_text("0\n")
    for service in ("web",):
        (rig.state / f"cid-{service}").write_text(f"{service}-original\n")
    return rig


def release(rig: Rig, bundle: bytes = b"reviewed bundle", digest: str | None = None):
    src = rig.home / "artifact-src/packaging/guard/releases"
    src.mkdir(parents=True)
    (src / BUNDLE).write_bytes(bundle)
    (src / f"{BUNDLE}.sha256").write_text(f"{digest or hashlib.sha256(bundle).hexdigest()}  {BUNDLE}\n")
    return rig.run(RID)


def api_image(rig: Rig) -> str:
    cid = (rig.state / "cid-api").read_text().strip()
    return (rig.state / f"image-{cid}").read_text().strip()


@pytest.fixture
def public(rig: Rig):
    """The stub answers 401 for the unauthenticated bundle route, 200 elsewhere."""
    curl = rig.stubs / "curl"
    curl.write_text(
        '#!/usr/bin/env bash\necho "curl $*" >> "$STATE/calls"\n'
        'case "$*" in *guards/download*) cat "$STATE/download-status" ;; *) cat "$STATE/public-status" ;; esac\n'
    )
    (rig.state / "download-status").write_text("401\n")


def test_release_recreates_only_api_without_building(rig: Rig, public) -> None:
    result = release(rig)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "GUARD BUNDLE RELEASE VERIFIED" in result.stdout
    assert api_image(rig) == NEW_API
    env = (rig.app / ".env").read_text()
    assert env.count("ACCESSPROOF_GUARD_RELEASE_VERSION=") == 1 and "VERSION=0.1.6" in env
    assert "docker build" not in rig.calls
    assert "alembic upgrade" not in rig.calls
    assert "--force-recreate api" in rig.calls
    for service in ("web", "worker", "db", "redis", "nginx"):
        assert f"--force-recreate {service}" not in rig.calls
    assert "nginx -s reload" in rig.calls
    for service in ("web", "worker", "db", "redis", "nginx"):
        assert (rig.state / f"cid-{service}").read_text().strip() == f"{service}-original"


def test_bundle_checksum_mismatch_changes_nothing(rig: Rig, public) -> None:
    result = release(rig, digest="0" * 64)
    assert result.returncode != 0
    assert "--force-recreate" not in rig.calls
    assert api_image(rig) == OLD_API


def test_missing_previous_image_refuses(rig: Rig, public) -> None:
    (rig.state / "no-previous-image").write_text("")
    result = release(rig)
    assert result.returncode != 0
    assert "rollback impossible" in result.stdout
    assert api_image(rig) == OLD_API


def test_open_download_rolls_back(rig: Rig, public) -> None:
    (rig.state / "download-status").write_text("200\n")
    result = release(rig)
    assert result.returncode != 0
    assert "API ROLLBACK VERIFIED" in result.stdout
    assert api_image(rig) == OLD_API
    assert "VERSION=0.1.5" in (rig.app / ".env").read_text()


def test_unset_version_rolls_back(rig: Rig, public) -> None:
    (rig.state / "no-version").write_text("")
    result = release(rig)
    assert result.returncode != 0
    assert api_image(rig) == OLD_API


def test_database_drift_refuses(rig: Rig, public) -> None:
    (rig.state / "db-revision").write_text("a1b2c3d4e5f6\n")
    result = release(rig)
    assert result.returncode != 0
    assert "docker create" not in rig.calls


def test_script_is_valid_and_builds_nothing() -> None:
    script = SCRIPTS / "deploy_guard_bundle_on_ec2.sh"
    assert subprocess.run(["bash", "-n", str(script)], check=False).returncode == 0
    code = [line for line in script.read_text().splitlines() if not line.lstrip().startswith("#")]
    assert not any("docker build" in line or "pip install" in line for line in code)
