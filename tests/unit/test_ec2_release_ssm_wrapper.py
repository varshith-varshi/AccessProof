"""Regression tests for the EC2 release SSM path.

r22's first SSM attempt (a10ad326-…) died instantly: AWS-RunShellScript runs
the joined ``commands`` under /bin/sh (dash on Ubuntu) and the wrapper began
with ``set -euo pipefail``. A second latent defect: the expected starting DB
revision defaulted to a stale value and a workstation env var never reached
the instance. These tests execute the generated wrapper under dash.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
REL_DIR = ROOT / "deploy" / "ec2-release"

spec = importlib.util.spec_from_file_location("ssm_payload", REL_DIR / "ssm_payload.py")
ssm_payload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ssm_payload)

SHA = "a" * 64
REV = "u5e6f7a8b9c0"
RID = "r23-rt-fixes-87e6a83aaaaa"


def _url(name: str) -> str:
    return (
        f"https://bucket-x.s3.eu-north-1.amazonaws.com/{name}"
        "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=deadbeef"
    )


def _payload(**over):
    args = dict(
        release_id=RID,
        artifact_sha256=SHA,
        expected_db_revision=REV,
        artifact_url=_url("artifact.tar"),
        file_urls={n: _url(n) for n in ssm_payload.STAGED_FILES},
    )
    args.update(over)
    return ssm_payload.build(**args)


def test_wrapper_is_posix_not_bash():
    cmds = _payload()["commands"]
    assert cmds[0] == "set -eu"
    joined = "\n".join(cmds)
    assert "pipefail" not in joined
    assert "[[" not in joined


def test_expected_revision_is_passed_on_the_remote_command():
    last = _payload()["commands"][-1]
    assert last.startswith(f"EXPECTED_DB_REVISION={REV} PUBLIC_CHECKS=1 bash ")
    assert last.endswith(f"/{RID}/deploy_on_ec2.sh {RID} /home/ubuntu/accessproof-releases/{RID}/artifact.tar {SHA}")


@pytest.mark.parametrize(
    "over",
    [
        {"expected_db_revision": ""},
        {"expected_db_revision": "u5e6f7a8b9c0; rm -rf /"},
        {"release_id": "R23 bad"},
        {"artifact_sha256": "xyz"},
        {"artifact_url": "https://evil.example.com/a"},
        {"artifact_url": _url("artifact.tar") + "'$(id)'"},
    ],
)
def test_rejects_unsafe_inputs(over):
    with pytest.raises(ValueError):
        _payload(**over)


@pytest.mark.skipif(shutil.which("dash") is None, reason="dash not installed")
def test_wrapper_executes_under_dash(tmp_path):
    releases = tmp_path / "releases"
    stub = tmp_path / "bin"
    stub.mkdir()
    record = tmp_path / "bash-invocation.txt"
    (stub / "curl").write_text('#!/bin/sh\nwhile [ $# -gt 1 ]; do [ "$1" = -o ] && touch "$2"; shift; done\n')
    (stub / "sha256sum").write_text("#!/bin/sh\ncat >/dev/null\nexit 0\n")
    (stub / "bash").write_text(
        f'#!/bin/sh\necho "EXPECTED_DB_REVISION=$EXPECTED_DB_REVISION $*" > {record}\n'
        f'echo "$PUBLIC_CHECKS" > {record}.pc\n'
    )
    for f in stub.iterdir():
        f.chmod(f.stat().st_mode | stat.S_IEXEC)

    script = "\n".join(_payload()["commands"]).replace(ssm_payload.RELEASES, str(releases))
    env = {"PATH": f"{stub}:/usr/bin:/bin"}
    first = subprocess.run(["dash", "-c", script], env=env, capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    rec = record.read_text().strip()
    assert rec.startswith(f"EXPECTED_DB_REVISION={REV} ")
    assert "PUBLIC_CHECKS" not in rec  # env prefix, not argv
    assert f"deploy_on_ec2.sh {RID} " in rec
    for name in ("artifact.tar", *ssm_payload.STAGED_FILES):
        assert (releases / RID / name).exists()

    # A release id is never reused.
    record.unlink()
    second = subprocess.run(["dash", "-c", script], env=env, capture_output=True, text=True)
    assert second.returncode == 2
    assert "refusing to reuse" in second.stderr
    assert not record.exists()


def test_rehearsal_disables_public_checks_production_does_not():
    assert " PUBLIC_CHECKS=0 " in _payload(public_checks=False)["commands"][-1]
    assert " PUBLIC_CHECKS=1 " in _payload()["commands"][-1]


def test_ship_rehearsal_refuses_production_instance():
    s = (REL_DIR / "ship_via_ssm.sh").read_text()
    assert '"$ACCESSPROOF_REHEARSAL_INSTANCE" != "$PRODUCTION_INSTANCE"' in s


def test_old_pipefail_wrapper_really_fails_under_dash():
    """Guards the premise: if dash ever accepted pipefail this test documents it."""
    if shutil.which("dash") is None:
        pytest.skip("dash not installed")
    r = subprocess.run(["dash", "-c", "set -euo pipefail; echo reached"], capture_output=True, text=True)
    assert r.returncode != 0 and "reached" not in r.stdout


def test_deploy_requires_explicit_expected_revision(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "EXPECTED_DB_REVISION"}
    r = subprocess.run(
        ["bash", str(REL_DIR / "deploy_on_ec2.sh"), RID, str(tmp_path / "a.tar"), SHA],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert "EXPECTED_DB_REVISION must be set" in r.stderr
    assert "r2b3c4d5e6f7}" not in (REL_DIR / "deploy_on_ec2.sh").read_text()


def test_ship_script_contract():
    s = (REL_DIR / "ship_via_ssm.sh").read_text()
    assert "set -euo pipefail\"" not in s and '"set -euo pipefail",' not in s
    assert '${2:?' in s and '${3:?' in s           # revision and label are required
    assert 'git show "$COMMIT:deploy/ec2-release/$f"' in s   # host scripts pinned to the commit
    assert "Status=='InProgress'" in s              # refuses while another SSM command runs
    assert "r22-least-privilege-" not in s           # no hard-coded release prefix


@pytest.mark.parametrize("name", ["deploy_on_ec2.sh", "rollback_on_ec2.sh", "enable_least_privilege_db.sh"])
def test_host_scripts_share_one_release_lock(name):
    s = (REL_DIR / name).read_text()
    assert "exec 9>>/home/ubuntu/accessproof-releases/.release.lock" in s
    assert "flock -n 9" in s
