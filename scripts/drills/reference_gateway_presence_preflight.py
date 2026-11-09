#!/usr/bin/env python3
"""Read-only, fail-closed preflight for the legacy 8443 reference Gateway.

Does not restart Docker, issue pairing, authenticate heartbeat or certify routes.
Never prints container environment values, bearer credentials or pairing tokens.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CONTAINER = "ap-remote-gateway"
IMAGE = "sha256:d2f3db8e7be57504fbbdb183cae8c5a9586a5c322788d766a2f027b46fd47219"
ORG = "48ee8c86-d4d8-4cde-b00b-bc779f965f4f"
APP = "sharepoint-rag-staging"
HOSTNAME = "ap-gateway.lab.internal"
PRESENCE = {
    "ACCESSPROOF_GATEWAY_PRESENCE_CONTROL_PLANE_URL",
    "ACCESSPROOF_GATEWAY_PRESENCE_ORGANIZATION_ID",
    "ACCESSPROOF_GATEWAY_PRESENCE_INSTALLATION_ID",
    "ACCESSPROOF_GATEWAY_PRESENCE_CREDENTIAL",
    "ACCESSPROOF_GATEWAY_PRESENCE_ROUTE_SHA256",
}


class Refused(Exception):
    pass


def inspect_gateway() -> dict[str, Any]:
    try:
        result = subprocess.run(
            ["docker", "inspect", CONTAINER],
            capture_output=True, check=True, text=True, timeout=15,
        )
        entries = json.loads(result.stdout)
        if not isinstance(entries, list) or len(entries) != 1:
            raise ValueError("invalid inspection response")
        entry: dict[str, Any] = entries[0]
        return entry
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise Refused("DOCKER_INSPECT_FAILED") from exc


def inspect_bindings(entry: dict[str, Any]) -> dict[str, Any]:
    config = entry.get("Config") or {}
    host = entry.get("HostConfig") or {}
    network = entry.get("NetworkSettings") or {}
    env = {k: v for line in config.get("Env", [])
           for k, sep, v in [line.partition("=")] if sep}
    port = (network.get("Ports") or {}).get("8443/tcp") or []
    networks = set((network.get("Networks") or {}).keys())
    checks = {
        "pinned_image": entry.get("Image") == IMAGE,
        "running": entry.get("State", {}).get("Status") == "running",
        "correct_org": env.get("ACCESSPROOF_GATEWAY_TENANT_ID") == ORG,
        "correct_application": env.get("ACCESSPROOF_GATEWAY_APPLICATION_ID") == APP,
        "private_8443": (
            len(port) == 1 and port[0].get("HostIp") == "127.0.0.1"
            and str(port[0].get("HostPort")) == "8443"
        ),
        "expected_networks": {"ap-remote-edge", "sharepoint-rag-lab_guard-internal"} <= networks,
        "read_only_root": host.get("ReadonlyRootfs") is True,
        "drop_caps": "ALL" in (host.get("CapDrop") or []),
        "no_new_privileges": "no-new-privileges" in " ".join(host.get("SecurityOpt") or []),
    }
    return {
        "checks": checks,
        "runtime_verified": all(checks.values()),
        "authenticated_presence_configured": PRESENCE <= set(env),
        "presence_keys_configured_count": len(PRESENCE & set(env)),
        "legacy_manual_runtime": not bool((config.get("Labels") or {}).get(
            "com.docker.compose.project"
        )),
    }


def verify_https_ready(ca: Path) -> bool:
    if not ca.is_file() or ca.is_symlink():
        raise Refused("TLS_CA_UNAVAILABLE")
    try:
        context = ssl.create_default_context(cafile=str(ca))
        with socket.create_connection(("127.0.0.1", 8443), timeout=5) as tcp:
            with context.wrap_socket(tcp, server_hostname=HOSTNAME) as conn:
                conn.settimeout(5)
                conn.sendall((
                    "GET /health/ready HTTP/1.1\r\n"
                    f"Host: {HOSTNAME}\r\nConnection: close\r\n\r\n"
                ).encode("ascii"))
                header = conn.recv(512)
        return header.startswith(b"HTTP/1.1 200 ") or header.startswith(b"HTTP/1.0 200 ")
    except (OSError, ssl.SSLError) as exc:
        raise Refused("PINNED_HTTPS_GATEWAY_NOT_READY") from exc


def pairing_status(path: Path | None, now: datetime | None = None) -> str:
    if path is None:
        return "NOT_PROVIDED"
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                    or not 80 <= info.st_size <= 4096):
                return "PRIVATE_FILE_REQUIRED"
            data = os.read(fd, 4097)
        finally:
            os.close(fd)
        p = json.loads(data)
        if (p.get("schema") != "accessproof.gateway_pairing/v1"
                or p.get("application_id") != APP or p.get("organization_id") != ORG
                or p.get("control_plane_url") != "https://api.accessproof.in"
                or not isinstance(p.get("pairing_token"), str)
                or len(p["pairing_token"]) < 32):
            return "WRONG_SCOPE"
        expiry = datetime.fromisoformat(p["expires_at"].replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            return "INVALID_EXPIRY"
        delta = (expiry - (now or datetime.now(timezone.utc))).total_seconds()
        return "FRESH_UNCONSUMED_NOT_VERIFIED" if 0 < delta <= 960 else "EXPIRED_OR_INVALID"
    except (OSError, ValueError, UnicodeError, TypeError, KeyError, AttributeError):
        return "UNREADABLE_OR_INVALID"


def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument("--ca-file", type=Path, default=Path.home() / ".ap-id/remote-gw/ca.pem")
    cli.add_argument("--pairing-file", type=Path)
    args = cli.parse_args()
    try:
        state = inspect_bindings(inspect_gateway())
        ready = verify_https_ready(args.ca_file)
        pairing = pairing_status(args.pairing_file)
        print(json.dumps({
            "application_id": APP, "container": CONTAINER,
            "runtime": state, "tls_8443_ready": ready, "pairing": pairing,
            "heartbeat_verified": False, "application_route_certified": False,
            "next_action": "OWNER_FRESH_PAIRING_LEGACY_MIGRATION_AND_REAL_ROUTE_CHALLENGE",
        }, sort_keys=True))
        return 0 if ready and state["runtime_verified"] else 2
    except Refused as exc:
        print(json.dumps({"status": "REFUSED", "reason": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
