"""register_gates_document.sh must use an explicit non-root profile and probe
permissions before any change. A stub `aws` records calls; AWS is never contacted."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy/deployer/register_gates_document.sh"

STUB = r'''#!/usr/bin/env bash
echo "PROFILE=${AWS_PROFILE:-} $*" >> "$AWS_STUB_LOG"
case "$*" in
  *"sts get-caller-identity"*) echo "$AWS_STUB_ARN" ;;
  *"ssm describe-document"*) echo "An error occurred (AccessDeniedException)" >&2; exit 254 ;;
  *"iam list-role-policies"*) echo "An error occurred (AccessDenied)" >&2; exit 254 ;;
  *) echo "MUTATION $*" >> "$AWS_STUB_LOG" ;;
esac
'''


def run(tmp_path, arn, profile=None):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    (bindir / "aws").write_text(STUB)
    (bindir / "aws").chmod(0o755)
    log = tmp_path / "calls.log"
    log.write_text("")
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env.update(PATH=f"{bindir}:{env['PATH']}", AWS_STUB_LOG=str(log), AWS_STUB_ARN=arn, TMPDIR=str(tmp_path))
    if profile is not None:
        env["AP_REGISTRAR_PROFILE"] = profile
    p = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60)
    return p, log.read_text()


def test_refuses_default_profile_without_calling_aws(tmp_path):
    p, calls = run(tmp_path, "arn:aws:iam::102076848988:root", profile="default")
    assert p.returncode == 2 and calls == ""


def test_refuses_root_session_before_any_change(tmp_path):
    p, calls = run(tmp_path, "arn:aws:iam::102076848988:root")
    assert p.returncode == 2 and "root" in p.stderr and "MUTATION" not in calls


def test_uses_explicit_non_root_profile_and_stops_on_missing_permission(tmp_path):
    p, calls = run(tmp_path, "arn:aws:iam::102076848988:user/accessproof-infra-admin")
    assert p.returncode == 3, p.stderr
    assert "ssm:DescribeDocument" in p.stderr and "iam:ListRolePolicies" in p.stderr
    assert "MUTATION" not in calls
    assert all(line.startswith("PROFILE=accessproof-infra-admin ") for line in calls.splitlines())


def test_refuses_deployer_identity(tmp_path):
    p, calls = run(tmp_path, "arn:aws:sts::102076848988:assumed-role/accessproof-production-deployer/x")
    assert p.returncode == 2 and "MUTATION" not in calls
