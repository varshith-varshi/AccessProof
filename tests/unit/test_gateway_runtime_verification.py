"""Gateway runtime verification must execute Docker with one argv vector."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from apps.gateway.accessproof_gateway import customer_connect


def test_existing_approved_runtime_is_inspected_without_invalid_subprocess_args(
    monkeypatch, tmp_path: Path, capsys,
) -> None:
    """Regression for the fresh-install path before a customer route changes."""
    source_file = tmp_path / "a" / "b" / "c" / "customer_connect.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_text("# test-only path")
    (tmp_path / "runtime-release.json").write_text(json.dumps({
        "schema": "accessproof.gateway_runtime/v1",
        "image": "accessproof-gateway:test",
        "image_id": "sha256:" + "a" * 64,
        "archive_sha256": "b" * 64,
    }))
    monkeypatch.setattr(customer_connect, "__file__", str(source_file))

    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        assert len(args) == 1
        assert args[0] == [
            "docker", "image", "inspect", "accessproof-gateway:test", "--format", "{{.Id}}",
        ]
        return subprocess.CompletedProcess(args[0], 0, stdout="sha256:" + "a" * 64 + "\n")

    monkeypatch.setattr(customer_connect.subprocess, "run", run)
    customer_connect.verify_and_prepare_gateway_runtime("accessproof-gateway:test")

    assert len(calls) == 1
    assert "Verified existing AccessProof Gateway runtime image." in capsys.readouterr().out
