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
    root = "/opt/accessproof-independent-status-src"
    cmds = [
        "set -euo pipefail",
        "umask 077",
        "mkdir -p "+root+"/scripts/certifier "+root+"/deploy/certifier/independent",
    ]

    # Purpose-bound source upload: AWS SSM limits individual shell commands.
    # Split base64 into bounded shell literals, then verify the SHA-256 of the
    # decompressed artifact BEFORE any installer runs. No keys or OAuth tokens.
    for payload, target, digest in (
        (code, root+"/scripts/certifier/independent_status_watcher.py", code_sha),
        (installer, root+"/deploy/certifier/independent/install_status_watcher.sh", installer_sha),
    ):
        partfile = target + ".b64"
        cmds.append(": > '"+partfile+"'")
        for i in range(0, len(payload), 2800):
            cmds.append("printf '%s' '"+payload[i:i+2800]+"' >> '"+partfile+"'")
        cmds.extend([
            "base64 -d '"+partfile+"' | gzip -d > '"+target+"'",
            "rm -f '"+partfile+"'",
            "echo '"+digest+"  "+target+"' | sha256sum -c",
        ])
    cmds.extend([
        "cd "+root,
        "bash deploy/certifier/independent/install_status_watcher.sh "+instance+" "+role+" "+key,
        "systemctl reset-failed accessproof-independent-certificate-status.service || true",
        # The watcher intentionally exits 2 when a source, app certificate, or
        # Gateway is degraded. Verify that observed state instead of reporting
        # a false bootstrap failure. Unexpected failures still halt the install.
        "if systemctl start accessproof-independent-certificate-status.service; then",
        "  echo WATCHER_OBSERVATION=UP",
        "else",
        "  code=$(systemctl show accessproof-independent-certificate-status.service -p ExecMainStatus --value)",
        "  result=$(systemctl show accessproof-independent-certificate-status.service -p Result --value)",
        "  [ \"$code\" = 2 ] && [ \"$result\" = exit-code ] || { echo WATCHER_UNEXPECTED_SERVICE_FAILURE >&2; exit 17; }",
        "  journalctl -u accessproof-independent-certificate-status.service -n 40 --no-pager --output=cat | python3 -c 'import json,sys; r=[json.loads(x) for x in sys.stdin if x.startswith(\"{\") and \"monitor_status\" in x]; assert r and r[-1][\"monitor_status\"] == \"DEGRADED\"' ",
        "  echo WATCHER_OBSERVATION=DEGRADED",
        "fi",
        "systemctl is-enabled accessproof-independent-certificate-status.timer",
        "systemctl is-active accessproof-independent-certificate-status.timer",
        "systemctl show accessproof-independent-certificate-status.service -p Result -p ExecMainStatus",
        "journalctl -u accessproof-independent-certificate-status.service -n 10 --no-pager --output=cat",
    ])
    if any(len(x)>3900 for x in cmds):
        raise RuntimeError("SSM_COMMAND_TOO_LARGE")
    return cmds


def main() -> int:
    # Reading --help must never submit a privileged SSM installation.
    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        print("Usage: python bootstrap_independent_status_ssm.py [--help]")
        print("Without arguments: re-install and run read-only watcher on pinned certifier EC2.")
        return 0
    if len(sys.argv) != 1:
        raise RuntimeError("UNEXPECTED_ARGUMENT")
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


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, KeyError, ValueError, IndexError) as exc:
        print("READ_ONLY_STATUS_INSTALLATION_BLOCKED:" + str(exc), file=sys.stderr)
        sys.exit(2)
