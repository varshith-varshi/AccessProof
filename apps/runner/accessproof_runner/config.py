"""Local runner configuration with a narrow, permission-safe storage boundary."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import platform
import tempfile


def state_dir() -> Path:
    return Path(os.getenv("ACCESSPROOF_RUNNER_STATE_DIR", "/var/lib/accessproof-runner"))


def credential_path() -> Path:
    return state_dir() / "credentials.json"


@dataclass(frozen=True)
class RunnerCredentials:
    api_url: str
    runner_id: str
    runner_secret: str
    name: str
    version: str


def capabilities() -> dict[str, list[str]]:
    """An explicit allowlist of this runner's executable product actions."""
    return {
        "sources": ["mock", "google_drive", "microsoft365", "confluence", "slack", "salesforce"],
        "ai_targets": ["generic_http", "demo_ai", "mock_rag"],
        "actions": [
            "source_connector.validate",
            "source_canary.create",
            "source_access.verify",
            "source_permission.revoke",
            "source_permission.restore",
            "ai_target.probe",
            "evidence.collect",
            "cleanup.execute",
        ],
    }


def host_platform() -> tuple[str, str]:
    return platform.system().lower(), platform.machine().lower()


def load_credentials() -> RunnerCredentials | None:
    path = credential_path()
    if not path.exists():
        return None
    if path.stat().st_mode & 0o077:
        raise RuntimeError("Runner credentials have unsafe file permissions")
    data = json.loads(path.read_text(encoding="utf-8"))
    return RunnerCredentials(**data)


def save_credentials(credentials: RunnerCredentials) -> None:
    directory = state_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    target = credential_path()
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=directory, prefix=".credentials-", delete=False
    ) as handle:
        json.dump(asdict(credentials), handle, sort_keys=True)
        handle.write("\n")
        temp_path = Path(handle.name)
    os.chmod(temp_path, 0o600)
    temp_path.replace(target)
    os.chmod(target, 0o600)


def delete_credentials() -> None:
    credential_path().unlink(missing_ok=True)
