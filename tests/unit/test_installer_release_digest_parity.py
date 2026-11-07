"""Prevent an apparently valid new ZIP from failing in the production deployer."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_all_releasers_require_the_identical_reviewed_gateway_digest():
    expected = "9db1c5a90e52e22097183c84c670a6dc71046d530a4c7627787d1344ba98ffc6"
    for relative in (
        "deploy/deployer/ship_production.sh",
        "deploy/ec2-release/deploy_web_only_on_ec2.sh",
        "deploy/ec2-release/deploy_on_ec2.sh",
        "deploy/ec2-release/deploy_api_only_on_ec2.sh",
    ):
        script = ROOT / relative
        contents = script.read_text()
        if relative.endswith("ship_production.sh"):
            match = re.search(r"^GATEWAY_ZIP_SHA=([0-9a-f]{64})$", contents, re.M)
        elif relative.endswith("deploy_web_only_on_ec2.sh"):
            match = re.search(r"^GATEWAY_SHA='([0-9a-f]{64})'$", contents, re.M)
        elif relative.endswith("deploy_api_only_on_ec2.sh"):
            match = re.search(r'^INSTALLER_SHA="([0-9a-f]{64})"$', contents, re.M)
        else:
            match = re.search(r'^EXPECTED_GATEWAY_INSTALLER_SHA256="([0-9a-f]{64})"$', contents, re.M)
        assert match, f"Missing pinned digest in {relative}"
        assert match.group(1) == expected, f"Inconsistent published installer in {relative}"
        assert subprocess.run(["bash", "-n", str(script)], capture_output=True).returncode == 0


def test_release_pin_validator_accepts_real_reviewed_zip_if_present():
    from scripts.verify_release_installer_pins import verify

    archive = Path.home() / "Downloads/accessproof-gateway-connector-20261107-manual-tls-r54.zip"
    if archive.exists():
        assert verify(archive) == "9db1c5a90e52e22097183c84c670a6dc71046d530a4c7627787d1344ba98ffc6"


def test_release_pin_validator_rejects_mismatched_server_pin(tmp_path):
    from scripts.verify_release_installer_pins import PINS, verify
    import hashlib
    import pytest

    archive = tmp_path / "reviewed.zip"
    archive.write_bytes(b"reviewed")
    good = hashlib.sha256(archive.read_bytes()).hexdigest()
    bad = "0" * 64
    for index, (name, _) in enumerate(PINS.items()):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if index == 0:
            path.write_text("GATEWAY_ZIP_SHA=" + good + "\n")
        elif index == 1:
            path.write_text("GATEWAY_SHA='" + bad + "'\n")
        elif index == 2:
            path.write_text('EXPECTED_GATEWAY_INSTALLER_SHA256="' + good + '"\n')
        else:
            path.write_text('INSTALLER_SHA="' + good + '"\n')
    with pytest.raises(ValueError, match="pin mismatch"):
        verify(archive, root=tmp_path)


def test_web_release_invokes_predeployment_digest_parity():
    script = (ROOT / "deploy/deployer/ship_production.sh").read_text()
    assert script.count('python3 "$REPO/scripts/verify_release_installer_pins.py" --zip "$GATEWAY_ZIP"') == 2
