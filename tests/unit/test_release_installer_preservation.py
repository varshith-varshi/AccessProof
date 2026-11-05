"""Offline tests of the release's pinned Gateway ZIP preservation preflight.

Never accesses production AWS, containers or customer secrets.
"""
from __future__ import annotations

import hashlib
import re
import shlex
import subprocess
import zipfile
from pathlib import Path

import pytest

RELEASE = Path(__file__).resolve().parents[2] / "deploy/ec2-release/deploy_on_ec2.sh"


def _preservation_function() -> str:
    text = RELEASE.read_text()
    match = re.search(
        r"^preserve_reviewed_gateway_installer\(\) \{.*?^\}\npreserve_reviewed_gateway_installer$",
        text, re.M | re.S,
    )
    assert match is not None, "Release helper is missing or renamed"
    return match.group(0)


def _exercise(tmp_path: Path, *, mode: str, source: Path | None, expected: str) -> subprocess.CompletedProcess[str]:
    dest = tmp_path / "release"
    dest.mkdir()
    (dest / "checksums.txt").write_text("")
    source_path = shlex.quote(str(source)) if source else "''"
    script = f"""
set -euo pipefail
REL={shlex.quote(str(dest))}
PUBLIC_CHECKS={'0' if mode == 'rehearsal' else '1'}
EXPECTED_GATEWAY_INSTALLER_SHA256={shlex.quote(expected)}
TEST_SOURCE={source_path}
log() {{ printf '%s\\n' "$*"; }}
compose() {{ if [[ "$1" == 'ps' && "$2" == '-q' && "$3" == 'web' ]]; then
  [[ -n "$TEST_SOURCE" ]] && printf 'synthetic-web-cid\\n'
fi; }}
docker() {{ if [[ "$1" == 'cp' ]]; then
  [[ -s "$TEST_SOURCE" ]] || return 2
  cp "$TEST_SOURCE" "$3"
else return 2; fi; }}
{_preservation_function()}
"""
    return subprocess.run(["bash", "-c", script], text=True, capture_output=True, timeout=15)


def _zip(tmp_path: Path, *, valid: bool = True) -> Path:
    target = tmp_path / "reviewed-installer.zip"
    if not valid:
        target.write_bytes(b"not a ZIP file")
        return target
    with zipfile.ZipFile(target, "w") as bundle:
        bundle.writestr("__main__.py", "print('synthetic fixture only')\n")
        bundle.writestr("accessproof-gateway-connector/accessproof-gateway-runtime.tar.gz", b"synthetic")
    return target


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_reviewed_installer_is_preserved_and_checksummed(tmp_path: Path) -> None:
    source = _zip(tmp_path)
    result = _exercise(tmp_path, mode="production", source=source, expected=_sha(source))
    assert result.returncode == 0, result.stdout + result.stderr
    preserved = tmp_path / "release/src/web-v2/public/downloads/accessproof-gateway-connector.zip"
    assert preserved.read_bytes() == source.read_bytes()
    assert _sha(source) in (tmp_path / "release/checksums.txt").read_text()


def test_modified_installer_checksum_blocks_release(tmp_path: Path) -> None:
    source = _zip(tmp_path)
    result = _exercise(tmp_path, mode="production", source=source, expected="0" * 64)
    assert result.returncode != 0
    assert "RELEASE REFUSED" in result.stdout


def test_corrupt_zip_blocks_release_even_with_matching_checksum(tmp_path: Path) -> None:
    source = _zip(tmp_path, valid=False)
    result = _exercise(tmp_path, mode="production", source=source, expected=_sha(source))
    assert result.returncode != 0


def test_missing_installer_blocks_production_release(tmp_path: Path) -> None:
    result = _exercise(tmp_path, mode="production", source=None, expected="0" * 64)
    assert result.returncode != 0
    assert "RELEASE REFUSED" in result.stdout


def test_rehearsal_without_real_zip_is_allowed(tmp_path: Path) -> None:
    result = _exercise(tmp_path, mode="rehearsal", source=None, expected="0" * 64)
    assert result.returncode == 0
    assert "rehearsal" in result.stdout


def test_noop_db_upgrade_does_not_trigger_downgrade_rollback_path() -> None:
    text = RELEASE.read_text()
    assert 'if [[ "$current_rev" != "$TARGET_DB_REVISION" ]]; then MIGRATED=1; fi' in text
    assert 'if (( MIGRATED )); then' in text


def test_release_script_is_syntactically_valid() -> None:
    assert subprocess.run(["bash", "-n", str(RELEASE)], check=False).returncode == 0
