"""Recovery and readiness checks for the *local* Human Validation RAG lab.

Runs without sudo or a laptop reboot. Docker restart policies still own process
startup; this only repairs stopped known lab containers and requests a refresh
from the trusted separate ingester if provenance is stale. Never disables Guard,
skips Gateway, signs inside the RAG, or claims health while the host is off.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HOME = Path.home()
STATE = HOME / ".config" / "accessproof" / "human-validation-recovery"
REPORT = STATE / "latest.json"
COOLDOWN = STATE / "last-ingester-restart"
APP = "accessproof-human-validation-rag"
CONTAINERS = (
    "accessproof-human-validation-rag-redis-1",
    "accessproof-guard-human-validation",
    "accessproof-human-validation-rag-ingest-1",
    "accessproof-human-validation-rag-model-1",
    "accessproof-human-validation-rag-accessproof-gateway-1",
    "accessproof-human-validation-rag-rag-1",
)
INGEST = "accessproof-human-validation-rag-ingest-1"
BRIDGE_UNIT = "accessproof-local-ollama-bridge.service"


def shell(*command: str, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, check=False, timeout=timeout)


def http_json(url: str, timeout: float = 4.0) -> tuple[int, dict]:
    try:
        with urlopen(Request(url, headers={"Cache-Control": "no-store"}), timeout=timeout) as r:
            try:
                return r.status, json.loads(r.read(100_000))
            except (ValueError, TypeError):
                return r.status, {}
    except HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read(100_000))
        except (ValueError, TypeError):
            return exc.code, {}
    except (URLError, TimeoutError, OSError):
        return 0, {}


def container_state(name: str) -> tuple[bool, str] | None:
    result = shell("docker", "inspect", "--format",
                   "{{.State.Running}}|{{.HostConfig.RestartPolicy.Name}}", name)
    if result.returncode != 0:
        return None
    parts = result.stdout.strip().split("|")
    if len(parts) != 2:
        return None
    return parts[0] == "true", parts[1]


def start_known_stopped_containers(*, recover: bool) -> tuple[dict, list[str]]:
    started = []
    details = {}
    for name in CONTAINERS:
        state = container_state(name)
        if state is None:
            details[name] = "MISSING_NOT_AUTOREINSTALLED"
            continue
        running, policy = state
        if running:
            details[name] = "RUNNING"
        elif recover:
            attempt = shell("docker", "start", name, timeout=30)
            if attempt.returncode == 0:
                started.append(name)
                details[name] = "STARTED"
            else:
                details[name] = "START_FAILED"
        else:
            details[name] = "STOPPED"
        if policy not in ("always", "unless-stopped"):
            details[name] += "_STARTUP_POLICY_MISSING"
    return details, started


def signed_index() -> dict:
    status, body = http_json("http://127.0.0.1:28189/health/ready")
    return {
        "http": status,
        "ready": status == 200 and body.get("signed_index_ready") is True,
        "reason": body.get("reason_code") if isinstance(body.get("reason_code"), str) else "RAG_UNAVAILABLE",
        "chunks": int(body.get("signed_chunks_valid") or 0),
        "earliest_expiry_seconds": int(body.get("oldest_signature_expires_in_seconds") or 0),
        "sync_age_seconds": body.get("last_sync_age_seconds"),
    }


def attempt_trusted_refresh(*, recover: bool, result: dict) -> str:
    if result["ready"] or not recover:
        return "NOT_NEEDED" if result["ready"] else "DRY_RUN"
    reason = result["reason"]
    allowed = {
        "ATTESTATION_EXPIRED_OR_NEAR_EXPIRY",
        "SOURCE_SYNC_STALE",
        "SIGNED_INDEX_EMPTY_OR_TOO_LARGE",
        "SIGNED_INDEX_UNAVAILABLE",
        "SIGNED_CONTENT_DIGEST_MISMATCH",
        "SIGNATURE_VERIFICATION_FAILED",
        "SIGNED_SOURCE_BINDING_MISMATCH",
        "SIGNED_INDEX_INSPECTION_FAILED",
    }
    if reason not in allowed:
        return "REQUIRES_INVESTIGATION_" + str(reason)[:80]
    if container_state(INGEST) != (True, "unless-stopped"):
        return "INGESTER_NOT_RUNNING"
    try:
        last = float(COOLDOWN.read_text().strip()) if COOLDOWN.exists() else 0.0
    except (ValueError, OSError):
        last = 0.0
    now = time.time()
    if now - last < 240:
        return "INGESTER_RESTART_COOLDOWN"
    # Persist cooldown first: repeated service invocations must not
    # constantly restart a failing Graph sync.
    tmp = COOLDOWN.with_name(COOLDOWN.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as out:
            out.write(str(now) + "\n")
        os.replace(tmp, COOLDOWN)
    finally:
        if tmp.exists():
            tmp.unlink()
    restarted = shell("docker", "restart", "--time", "8", INGEST, timeout=30)
    if restarted.returncode != 0:
        return "TRUSTED_INGESTER_RESTART_FAILED"
    for _ in range(12):
        time.sleep(3)
        if signed_index()["ready"]:
            return "SIGNED_INDEX_REFRESH_RECOVERED"
    return "WAITING_FOR_TRUSTED_GRAPH_REFRESH"


def local_model_ready() -> dict:
    # An HTTP 200 from Ollama proves its service is available, not that every
    # model generation succeeds. This is supplementary to fail-closed Gateway.
    code, body = http_json("http://127.0.0.1:11434/api/tags")
    models = body.get("models") if isinstance(body.get("models"), list) else []
    installed = any(isinstance(row, dict) and
                    str(row.get("name", "")).startswith("llama3.2:3b") for row in models)
    try:
        with socket.create_connection(("192.168.144.1", 11436), timeout=2):
            bridge = True
    except OSError:
        bridge = False
    return {"ollama_http": code, "pinned_model_installed": installed,
            "bridge_listening": bridge, "ready": code == 200 and installed and bridge}


def write_private_report(payload: dict) -> None:
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE, 0o700)
    target = REPORT.with_name(REPORT.name + ".tmp")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as file:
            json.dump(payload, file, indent=2, sort_keys=True)
            file.write("\n")
        os.replace(target, REPORT)
    finally:
        if target.exists():
            target.unlink()
    os.chmod(REPORT, 0o600)


def run(recover: bool) -> int:
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE, 0o700)
    docker = shell("docker", "info", "--format", "{{.ServerVersion}}", timeout=8)
    if docker.returncode != 0:
        payload = {"timestamp": int(time.time()), "ready": False,
                   "reason": "DOCKER_DAEMON_UNAVAILABLE"}
        write_private_report(payload)
        print(json.dumps(payload, sort_keys=True))
        return 2

    if recover and shell("systemctl", "--user", "is-active", BRIDGE_UNIT).returncode != 0:
        shell("systemctl", "--user", "start", BRIDGE_UNIT, timeout=15)
    containers, started = start_known_stopped_containers(recover=recover)
    if started:
        time.sleep(7)
    source_before = signed_index()
    action = attempt_trusted_refresh(recover=recover, result=source_before)
    source_after = signed_index()
    guard_http, guard = http_json(
        "http://127.0.0.1:18080/health?application_id=" + APP
    )
    gateway_http, _ = http_json("http://127.0.0.1:18090/health/ready")
    model = local_model_ready()
    all_running = len(containers) == len(CONTAINERS) and all(
        value in {"RUNNING", "STARTED"} for value in containers.values()
    )
    guard_ready = bool(guard_http == 200 and guard.get("ready") is True
                       and guard.get("status") == "ok")
    gateway_ready = gateway_http == 200
    ready = bool(all_running and source_after["ready"] and guard_ready
                 and gateway_ready and model["ready"])
    payload = {
        "timestamp": int(time.time()),
        "ready": ready,
        "purpose": "LAB_HOST_RECOVERY_NOT_INDEPENDENT_CERTIFICATION",
        "containers": containers,
        "started_containers": started,
        "source_signed_evidence": source_after,
        "source_refresh_action": action,
        "guard_ready": guard_ready,
        "gateway_ready": gateway_ready,
        "local_model": model,
        "employee_login": "SEPARATE_INTERACTIVE_ENTRA_SIGN_IN_REQUIRED_AFTER_RESTART",
    }
    write_private_report(payload)
    print(json.dumps({k: v for k, v in payload.items()
                      if k not in ("containers",)}, sort_keys=True))
    return 0 if ready else 2


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    mode = cli.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="read-only health check")
    mode.add_argument("--recover", action="store_true", help="start missing lab processes and refresh trusted ingestion")
    args = cli.parse_args()
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE, 0o700)
    lock_path = STATE / "recovery.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("RECOVERY_CHECK_ALREADY_RUNNING")
            sys.exit(0)
        sys.exit(run(recover=args.recover))
    finally:
        os.close(fd)
