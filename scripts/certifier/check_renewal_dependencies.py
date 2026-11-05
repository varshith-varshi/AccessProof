"""Read-only local prerequisite report for laptop-hosted certificate renewal.

Never reads or prints certificate private keys, employee tokens, signing material,
configuration contents, environment variables, or unredacted service logs.
Not an actual renewal or a substitute for an independent certifier host.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

UNITS = (
    "accessproof-route-attestation.timer",
    "accessproof-cert-renewal.timer",
    "accessproof-cert-renewal-pilot.timer",
)


def unit_active(name: str) -> bool:
    result = subprocess.run(["systemctl", "--user", "is-active", "--quiet", name],
                            capture_output=True, check=False, timeout=5)
    return result.returncode == 0


def secure_regular_file(path: Path) -> bool:
    try:
        st = path.lstat()
        return stat.S_ISREG(st.st_mode) and not (stat.S_IMODE(st.st_mode) & 0o077)
    except OSError:
        return False


def socket_present(path: Path) -> bool:
    try:
        return stat.S_ISSOCK(path.lstat().st_mode)
    except OSError:
        return False


def report(home: Path) -> dict:
    timers = {name: unit_active(name) for name in UNITS}
    result = {
        "host": "local-certifier-dependency-report",
        "timers_active": timers,
        "offline_signer_file_private": secure_regular_file(
            home / ".config/accessproof/certifier/ap-certifier-2026-11.pem"),
        "employee_sockets_present": {
            employee: socket_present(home / f".ap-id/{employee}.sock")
            for employee in ("alice", "bob")
        },
        "route_config_private": secure_regular_file(home / ".config/accessproof/remote-routes.json"),
        "tunnel_service_active": unit_active("accessproof-remote-rag-tunnel.service"),
        "migration_complete": False,  # This tool never claims migration.
    }
    result["local_prerequisites_present"] = (
        all(timers.values()) and result["offline_signer_file_private"]
        and all(result["employee_sockets_present"].values())
        and result["route_config_private"] and result["tunnel_service_active"]
    )
    return result


def main() -> int:
    result = report(Path(os.path.expanduser("~")))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["local_prerequisites_present"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
