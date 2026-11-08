#!/usr/bin/env python3
"""Self-heal local Guards that lost container DNS after a laptop network change.

    python scripts/certifier/guard_dns_recovery.py [--recover] [--cooldown-min 15]

On 2026-11-08 the pilot Guard failed every protected request closed for hours
(POLICY_SYNC_STALE, sync_error ConnectError): Docker's embedded DNS kept a stale
upstream after the laptop changed networks. ``docker restart`` fixes it and does
not change the attested route binding.

A Guard is restarted ONLY when all hold:
  * its /health reports not ready with a transport sync error (ConnectError/
    ConnectTimeout/...), and
  * the control-plane host does NOT resolve inside the container while it DOES
    resolve on this host (proves the stale-DNS condition), and
  * no route certification/attestation run is active (a restart would disturb
    its fail-closed probes), and
  * the per-container cooldown has elapsed.
Any other failure is only reported. A restarting Guard fails closed, so this can
only restore service, never weaken authorization. Prints one JSON line.
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.certifier.renewal_watchdog import DEFAULT_GUARD_URL  # noqa: E402

CONTROL_PLANE_HOST = "api.accessproof.in"
DEFAULT_GUARD_CONTAINER = "accessproof-guard"
TRANSPORT_ERRORS = ("ConnectError", "ConnectTimeout", "ReadTimeout", "RemoteProtocolError", "NetworkError")
STATE = Path.home() / ".ap-id/guard-dns-recovery"
BUSY_UNITS = (
    "accessproof-route-attestation.service",
    "accessproof-cert-renewal.service",
    "accessproof-cert-renewal-pilot.service",
)
CERTIFICATION_SCRIPTS = (
    b"remote_route_certification.py",
    b"remote_route_attestation.py",
    b"renew_source_certificate.py",
)


def guards(home: Path) -> dict[str, str]:
    """{loopback guard URL: container name} for the certified routes."""
    try:
        routes = json.loads((home / ".config/accessproof/remote-routes.json").read_text())
    except (OSError, ValueError):
        return {}
    out = {}
    for r in routes:
        env = r.get("env") or {}
        url = env.get("AP_RT_GUARD_URL") or DEFAULT_GUARD_URL
        if urlparse(url).hostname in ("127.0.0.1", "localhost"):
            out[url] = env.get("AP_GUARD_CONTAINER") or DEFAULT_GUARD_CONTAINER
    return out


def health(url: str) -> dict | None:
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/health", timeout=5) as r:  # noqa: S310 (loopback)
            return json.loads(r.read())
    except (OSError, ValueError):
        return None


def container_resolves(container: str, host: str) -> bool | None:
    """True if DNS works, False only for a proven DNS error, None if probe fails.

    A missing container, Docker permission error, or missing Python interpreter
    must NEVER be mistaken for stale DNS and trigger a container restart.
    """
    code = (
        "import socket, sys\n"
        "try:\n"
        f"    socket.getaddrinfo({host!r}, 443)\n"
        "except socket.gaierror:\n"
        "    print('DNS_FAILURE')\n"
        "    sys.exit(32)\n"
        "print('DNS_OK')\n"
    )
    try:
        p = subprocess.run(["docker", "exec", container, "python", "-c", code],
                           capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if p.returncode == 0 and p.stdout.strip() == "DNS_OK":
        return True
    if p.returncode == 32 and p.stdout.strip() == "DNS_FAILURE":
        return False
    return None


def host_resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, 443)
        return True
    except OSError:
        return False


def busy() -> bool:
    """Do not restart a Guard during systemd OR manually started certification."""
    for unit in BUSY_UNITS:
        p = subprocess.run(["systemctl", "--user", "is-active", unit], capture_output=True, text=True)
        if p.stdout.strip() in ("active", "activating", "deactivating"):
            return True
    # A manual certifier may run outside systemd. Match a whole argv entry,
    # not a free-text shell command or this recovery process's source code.
    for proc in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            argv = proc.read_bytes().split(b"\0")
        except OSError:
            continue
        if any(arg.endswith(name) for arg in argv for name in CERTIFICATION_SCRIPTS):
            return True
    return False


def decide(h: dict | None, *, container_dns: bool | None, host_dns: bool, is_busy: bool,
           cooled: bool) -> str:
    """Pure decision so it can be tested exhaustively."""
    if h is None:
        return "UNREACHABLE_REPORT_ONLY"
    if h.get("ready") is True:
        return "OK"
    if str(h.get("sync_error") or "") not in TRANSPORT_ERRORS:
        return "NOT_READY_REPORT_ONLY"
    if container_dns is not False or not host_dns:
        return "NOT_DNS_REPORT_ONLY"
    if is_busy:
        return "DEFERRED_CERTIFICATION_RUNNING"
    if not cooled:
        return "DEFERRED_COOLDOWN"
    return "RESTART"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--recover", action="store_true", help="restart a Guard that meets every condition")
    p.add_argument("--cooldown-min", type=float, default=15)
    a = p.parse_args()
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    report, problem = {}, False
    for url, container in sorted(guards(Path.home()).items()):
        h = health(url)
        needs_dns = h is not None and h.get("ready") is not True and str(h.get("sync_error") or "") in TRANSPORT_ERRORS
        cdns = container_resolves(container, CONTROL_PLANE_HOST) if needs_dns else None
        stamp = STATE / f"{container}.last-restart"
        cooled = not stamp.exists() or time.time() - stamp.stat().st_mtime > a.cooldown_min * 60
        action = decide(h, container_dns=cdns, host_dns=host_resolves(CONTROL_PLANE_HOST),
                        is_busy=busy() if needs_dns else False, cooled=cooled)
        entry = {"container": container, "action": action, "sync_error": (h or {}).get("sync_error")}
        if action == "RESTART" and a.recover:
            stamp.touch()
            ok = subprocess.run(["docker", "restart", "--time", "8", container],
                                capture_output=True, timeout=60).returncode == 0
            for _ in range(24):
                h2 = health(url)
                if h2 and h2.get("ready") is True:
                    break
                time.sleep(5)
            entry.update(restarted=ok, ready_after=bool(h2 and h2.get("ready") is True))
            problem |= not entry["ready_after"]
        elif action != "OK":
            problem = True
        report[url] = entry
    print(json.dumps({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "guards": report}), flush=True)
    return 1 if problem else 0


if __name__ == "__main__":
    sys.exit(main())
