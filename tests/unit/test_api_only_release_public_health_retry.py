"""Regression: an API/Nginx restart must not cause overlapping rollback traps."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

SERVER = Path(__file__).resolve().parents[2] / "deploy/ec2-release/deploy_api_only_on_ec2.sh"


def _health_func() -> str:
    script = SERVER.read_text()
    match = re.search(r"(?ms)^public_health\(\)\{\n.*?^\}\n(?=rollback\(\)\{)", script)
    assert match is not None, "expected explicit retryable public health function"
    return match.group(0)


def _run(mode: str, tmp_path: Path, *, err_trap: bool = False) -> tuple[subprocess.CompletedProcess, int]:
    counter = tmp_path / "curl_count"
    counter.write_text("0")
    body = """#!/usr/bin/env bash
set -euo pipefail
curl(){
  local n
  n=$(cat "$MOCK_COUNTER")
  n=$((n + 1))
  printf '%s' "$n" > "$MOCK_COUNTER"
  case "$MOCK_MODE" in
    transient)
      if (( n < 3 )); then return 55; fi
      printf '200'; return 0 ;;
    failure)
      printf '503'; return 0 ;;
    *)
      printf '200'; return 0 ;;
  esac
}
sleep(){ :; }
""" + _health_func()
    if err_trap:
        # With inherited -E error traps, failures inside the function can
        # trigger repeated rollbacks. Only the top-level failure may trap.
        body += """trap 'echo ROLLBACK_ONCE' ERR
public_health
"""
    else:
        body += """if public_health; then echo PASS; else echo FAIL; fi
"""
    cmd = subprocess.run(
        ["bash", "-c", body], text=True, capture_output=True, timeout=10,
        env={**os.environ, "MOCK_COUNTER": str(counter), "MOCK_MODE": mode},
    )
    return cmd, int(counter.read_text())


def test_retry_transient_socket_reset_succeeds(tmp_path):
    result, count = _run("transient", tmp_path)
    assert result.returncode == 0
    assert result.stdout.strip() == "PASS"
    assert count == 3
    assert not result.stderr


def test_never_claims_health_on_persistent_503(tmp_path):
    result, count = _run("failure", tmp_path)
    assert result.returncode == 0
    assert result.stdout.strip() == "FAIL"
    assert count == 12
    assert "NOT_200_WITHIN_RETRY_WINDOW" in result.stderr


def test_persistent_failure_invokes_one_rollback_trap(tmp_path):
    assert "set -Eeuo pipefail" not in SERVER.read_text()
    result, count = _run("failure", tmp_path, err_trap=True)
    assert result.returncode != 0
    assert count == 12
    assert result.stdout.count("ROLLBACK_ONCE") == 1
    assert "PUBLIC_API_HEALTH_NOT_200" in result.stderr


def test_retry_does_not_remove_safety_checks():
    content = SERVER.read_text()
    for required in (
        "PUBLIC_CHECKS", "expected production database revision", "health api 240",
        "health worker 120", "reload_nginx", "rollback()", "public_health",
        "pg_dump", "pg_restore", "installer",
    ):
        if required == "installer":
            assert "INSTALLER_SHA" in content
        else:
            assert required in content
    assert "--force-recreate web" not in content
    assert "docker system prune" not in content
    assert subprocess.run(["bash", "-n", str(SERVER)], check=False).returncode == 0
