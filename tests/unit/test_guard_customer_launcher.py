"""Realistic customer launcher smoke checks with a mocked Docker CLI.

Never starts an actual container or reaches a real Guard endpoint.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


def _fake_executable(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)


def test_linux_customer_launcher_reads_port_from_dotenv(tmp_path: Path) -> None:
    shutil.copy(REPO / "packaging/guard/start.sh", tmp_path / "start.sh")
    (tmp_path / ".env").write_text("GUARD_PORT=18081\n", encoding="utf-8")
    (tmp_path / "fakebin").mkdir()
    for executable in ("docker", "curl", "xdg-open"):
        _fake_executable(tmp_path / "fakebin" / executable, "exit 0\n")
    env = os.environ.copy()
    env.pop("GUARD_PORT", None)
    env["PATH"] = str(tmp_path / "fakebin") + os.pathsep + env["PATH"]
    result = subprocess.run(
        ["sh", str(tmp_path / "start.sh")], cwd=tmp_path, env=env,
        capture_output=True, text=True, timeout=5, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "http://127.0.0.1:18081/setup" in result.stdout


def test_linux_customer_launcher_prefers_explicit_port_override(tmp_path: Path) -> None:
    shutil.copy(REPO / "packaging/guard/start.sh", tmp_path / "start.sh")
    (tmp_path / ".env").write_text("GUARD_PORT=18081\n", encoding="utf-8")
    (tmp_path / "fakebin").mkdir()
    for executable in ("docker", "curl", "xdg-open"):
        _fake_executable(tmp_path / "fakebin" / executable, "exit 0\n")
    env = os.environ.copy()
    env["GUARD_PORT"] = "18082"
    env["PATH"] = str(tmp_path / "fakebin") + os.pathsep + env["PATH"]
    result = subprocess.run(
        ["sh", str(tmp_path / "start.sh")], cwd=tmp_path, env=env,
        capture_output=True, text=True, timeout=5, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "http://127.0.0.1:18082/setup" in result.stdout


def test_linux_customer_launcher_accepts_quoted_dotenv_port(tmp_path: Path) -> None:
    shutil.copy(REPO / "packaging/guard/start.sh", tmp_path / "start.sh")
    (tmp_path / ".env").write_text('GUARD_PORT="18083"\n', encoding="utf-8")
    (tmp_path / "fakebin").mkdir()
    for executable in ("docker", "curl", "xdg-open"):
        _fake_executable(tmp_path / "fakebin" / executable, "exit 0\n")
    env = os.environ.copy()
    env.pop("GUARD_PORT", None)
    env["PATH"] = str(tmp_path / "fakebin") + os.pathsep + env["PATH"]
    result = subprocess.run(
        ["sh", str(tmp_path / "start.sh")], cwd=tmp_path, env=env,
        capture_output=True, text=True, timeout=5, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "http://127.0.0.1:18083/setup" in result.stdout


def test_linux_customer_launcher_rejects_invalid_port_before_docker(tmp_path: Path) -> None:
    shutil.copy(REPO / "packaging/guard/start.sh", tmp_path / "start.sh")
    (tmp_path / ".env").write_text("GUARD_PORT=not-a-port\n", encoding="utf-8")
    (tmp_path / "fakebin").mkdir()
    for executable in ("docker", "curl"):
        _fake_executable(tmp_path / "fakebin" / executable, "exit 0\n")
    env = os.environ.copy()
    env.pop("GUARD_PORT", None)
    env["PATH"] = str(tmp_path / "fakebin") + os.pathsep + env["PATH"]
    result = subprocess.run(
        ["sh", str(tmp_path / "start.sh")], cwd=tmp_path, env=env,
        capture_output=True, text=True, timeout=5, check=False,
    )
    assert result.returncode != 0
    assert "Invalid GUARD_PORT" in result.stdout
