"""Prevent an apparently valid new ZIP from failing in the production deployer."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_all_releasers_require_the_identical_reviewed_gateway_digest():
    expected = "bab5f15f62c5186235677e489d7020654e72600d1f999a83554fa160a5dd91d9"
    for relative in (
        "deploy/deployer/ship_production.sh",
        "deploy/ec2-release/deploy_web_only_on_ec2.sh",
        "deploy/ec2-release/deploy_on_ec2.sh",
    ):
        script = ROOT / relative
        contents = script.read_text()
        if relative.endswith("ship_production.sh"):
            match = re.search(r"^GATEWAY_ZIP_SHA=([0-9a-f]{64})$", contents, re.M)
        elif relative.endswith("deploy_web_only_on_ec2.sh"):
            match = re.search(r"^GATEWAY_SHA='([0-9a-f]{64})'$", contents, re.M)
        else:
            match = re.search(r'^EXPECTED_GATEWAY_INSTALLER_SHA256="([0-9a-f]{64})"$', contents, re.M)
        assert match, f"Missing pinned digest in {relative}"
        assert match.group(1) == expected, f"Inconsistent published installer in {relative}"
        assert subprocess.run(["bash", "-n", str(script)], capture_output=True).returncode == 0
