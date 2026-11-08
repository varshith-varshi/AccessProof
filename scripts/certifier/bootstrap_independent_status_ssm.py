#!/usr/bin/env python3
"""Install the host's read-only production certificate status timer through SSM.

Uses a restricted operator role, checks existing CloudFormation outputs, sends
only version-controlled public Python/bash code, and never imports or signs.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

from bootstrap_independent_host_ssm import aws, encoded, verify_target

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "scripts/certifier/independent_status_watcher.py"
INSTALL = ROOT / "deploy/certifier/independent/install_status_watcher.sh"


def make_commands(instance: str, role: str, key: str) -> list[str]:
    code, code_sha = encoded(SRC)
    installer, installer_sha = encoded(INSTALL)
    cmds = [
        "set -euo pipefail",
        "mkdir -p /opt/accessproof-independent-status-src/scripts/certifier /opt/accessproof-independent-status-src/deploy/certifier/independent",
        "printf '%s' '"+code+"' | base64 -d | gzip -d > /opt/accessproof-independent-status-src/scripts/certifier/independent_status_watcher.py",
        "printf '%s' '"+installer+"' | base64 -d | gzip -d > /opt/accessproof-independent-status-src/deploy/certifier/independent/install_status_watcher.sh",
        "echo '"+code_sha+"  /opt/accessproof-independent-status-src/scripts/certifier/independent_status_watcher.py' | sha256sum -c",
        "echo '"+installer_sha+"  /opt/accessproof-independent-status-src/deploy/certifier/independent/install_status_watcher.sh' | sha256sum -c",
        "cd /opt/accessproof-independent-status-src",
        "bash deploy/certifier/independent/install_status_watcher.sh "+instance+" "+role+" "+key,
        "systemctl reset-failed accessproof-independent-certificate-status.service || true",
        "systemctl start accessproof-independent-certificate-status.service",
        "systemctl show accessproof-independent-certificate-status.service -p Result -p ExecMainStatus",
        "journalctl -u accessproof-independent-certificate-status.service -n 10 --no-pager --output=cat",
    ]
    if any(len(x)>3900 for x in cmds):
        raise RuntimeError("SSM_COMMAND_TOO_LARGE")
    return cmds


def main() -> int:
    instance, role, key = verify_target()
    params={"commands": make_commands(instance,role,key), "executionTimeout":["220"]}
    with tempfile.NamedTemporaryFile("w",prefix="ap-certifier-readonly-status-",suffix=".json",delete=False) as out:
        temp=Path(out.name)
        os.fchmod(out.fileno(),0o600)
        json.dump(params,out)
    try:
        response=aws("ssm","send-command","--document-name","AWS-RunShellScript",
                     "--instance-ids",instance,"--parameters","file://"+str(temp),
                     "--comment","Install purpose-bound READ-ONLY certificate status watcher")
    finally:
        temp.unlink(missing_ok=True)
    print(json.dumps({"command_id":response["Command"]["CommandId"],
                      "instance":instance,"phase":"READ_ONLY_STATUS_WATCHER",
                      "signing_enabled":False,"renewal_independent":False},sort_keys=True))
    return 0


if __name__=="__main__":
    try: sys.exit(main())
    except (RuntimeError,KeyError,ValueError,IndexError) as exc:
        print("READ_ONLY_STATUS_INSTALLATION_BLOCKED:"+str(exc),file=sys.stderr)
        sys.exit(2)
