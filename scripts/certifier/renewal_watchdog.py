"""Read-only local certificate renewal watchdog.

Reports only status and time-to-expiry; does not read/print cryptographic
private key material or employee session contents, and never issues certificates.
A green result means the *local* scheduler is ready, not off-host resilience.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import urllib.request
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.certifier.check_renewal_dependencies import report as dependency_report


def aware(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timezone-aware timestamp required")
    return parsed.astimezone(timezone.utc)


def inspect_certificates(directory: Path, now: datetime) -> dict[str, dict]:
    results = {}
    for path in sorted(directory.glob("*.certificate.json")):
        name = path.name.removesuffix(".certificate.json")
        if ".run-" in name:
            continue  # per-run output of a (possibly failed) certification, not the active certificate
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError("Unsafe certificate file")
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("status") != "CERTIFIED" or not payload.get("signature"):
                raise ValueError("Certificate is not certified and signed")
            expiry = aware(payload["expires_at"])
            remaining = round((expiry - now).total_seconds() / 3600, 2)
            state = "EXPIRED" if remaining <= 0 else "URGENT" if remaining <= 48 else "WATCH" if remaining <= 96 else "OK"
            results[name] = {"status": state, "hours_remaining": remaining}
        except (OSError, ValueError, KeyError, TypeError):
            results[name] = {"status": "INVALID_CERTIFICATE_METADATA"}
    return results


def last_attestations(path: Path, names: set[str], now: datetime) -> dict[str, dict]:
    latest = {}
    try:
        if path.is_symlink() or path.stat().st_size > 20_000_000:
            raise ValueError("Unsafe or unexpectedly large log")
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
                name = item.get("route")
                if name not in names:
                    continue
                at = aware(item["at"])
                if at > now:
                    continue
                if name not in latest or at > latest[name]["at"]:
                    latest[name] = {"at": at, "ok": item.get("ok") is True, "action": item.get("action")}
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                continue
    except (OSError, ValueError):
        pass
    results = {}
    for name in sorted(names):
        event = latest.get(name)
        if event is None:
            results[name] = {"status": "NO_RECENT_ATTESTATION"}
        else:
            hours_ago = round((now - event["at"]).total_seconds() / 3600, 2)
            status = "ATTESTATION_FAILED" if not event["ok"] else "ATTESTATION_STALE" if hours_ago >= 24 else "OK"
            results[name] = {"status": status, "hours_since_event": hours_ago}
    return results


EMPLOYEES = ("alice", "bob")
RECERTIFY_HOURS = 48       # remote_route_attestation.py --recertify-days default
TIMER_PERIOD_HOURS = 12    # accessproof-route-attestation.timer cadence
WATCH_HOURS = 96


def _socket_query(path: Path, what: str, timeout: float = 5.0) -> str:
    """Ask an employee session socket for NON-SECRET metadata only."""
    if what not in ("session", "claims"):
        raise ValueError("only non-secret queries are allowed")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(str(path))
        s.sendall((what + "\n").encode())
        data = b""
        while not data.endswith(b"\n") and len(data) < 65536:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.decode().strip()


def employee_sessions(home: Path) -> dict[str, dict]:
    """Liveness and wall-clock end of each employee session; never tokens."""
    results = {}
    for actor in EMPLOYEES:
        path = home / f".ap-id/{actor}.sock"
        try:
            alive = _socket_query(path, "claims").startswith("{")
        except OSError:
            alive = False
        if not alive:
            results[actor] = {"status": "UNAVAILABLE"}
            continue
        try:
            reply = json.loads(_socket_query(path, "session"))
            results[actor] = {"status": "OK", "session_expires_at": aware(reply["session_expires_at"]).isoformat()}
        except (OSError, ValueError, KeyError, TypeError):
            # Sessions started before lifetime reporting existed cannot say when
            # they end; that is a warning, never a pass.
            results[actor] = {"status": "LIFETIME_UNKNOWN"}
    return results


def recertification_window_end(certificates: dict[str, dict], now: datetime) -> datetime | None:
    """Latest time a live employee session is needed for the pending recertification(s)."""
    due = [now + timedelta(hours=max(m["hours_remaining"] - RECERTIFY_HOURS, 0) + TIMER_PERIOD_HOURS)
           for m in certificates.values()
           if isinstance(m.get("hours_remaining"), (int, float)) and 0 < m["hours_remaining"] <= WATCH_HOURS]
    return max(due) if due else None


def session_warnings(sessions: dict[str, dict], needed_until: datetime | None) -> list[str]:
    if needed_until is None:
        return []
    warnings = []
    for actor, info in sorted(sessions.items()):
        if info.get("status") == "UNAVAILABLE":
            warnings.append(f"EMPLOYEE_SESSION_UNAVAILABLE:{actor}")
        elif info.get("status") != "OK":
            warnings.append(f"EMPLOYEE_SESSION_LIFETIME_UNKNOWN:{actor}")
        elif aware(info["session_expires_at"]) < needed_until:
            warnings.append(f"EMPLOYEE_SESSION_EXPIRES_BEFORE_RECERTIFICATION:{actor}")
    return warnings


DEFAULT_GUARD_URL = "http://127.0.0.1:8080"


def guard_urls(home: Path) -> list[str]:
    """Loopback Guard URLs used by the certified routes (never a remote host)."""
    cfg = home / ".config/accessproof/remote-routes.json"
    try:
        routes = json.loads(cfg.read_text())
    except (OSError, ValueError):
        return []
    urls = {(r.get("env") or {}).get("AP_RT_GUARD_URL") or DEFAULT_GUARD_URL for r in routes if isinstance(r, dict)}
    return sorted(u for u in urls if urlparse(u).hostname in ("127.0.0.1", "localhost"))


def guard_readiness(urls: list[str], fetch=None) -> dict[str, dict]:
    """Non-secret /health of each local Guard. A Guard that is not ready fails
    every protected request closed (e.g. POLICY_SYNC_STALE), so it must alert even
    while route certificates and attestations look healthy."""
    def _get(url: str) -> dict:
        with urllib.request.urlopen(url.rstrip("/") + "/health", timeout=5) as r:  # noqa: S310 (loopback only)
            return json.loads(r.read())
    fetch = fetch or _get
    out = {}
    for url in urls:
        try:
            h = fetch(url)
            ready = h.get("ready") is True and h.get("policy_fresh") is not False
            out[url] = {"status": "OK" if ready else "NOT_READY", "sync_error": h.get("sync_error"),
                        "policy_fresh": h.get("policy_fresh")}
        except (OSError, ValueError) as exc:
            out[url] = {"status": "UNREACHABLE", "sync_error": type(exc).__name__}
    return out


def check(home: Path, now: datetime, *, prerequisites: dict | None = None,
          sessions: dict | None = None, guards: dict | None = None) -> dict:
    dependencies = prerequisites if prerequisites is not None else dependency_report(home)
    certificates = inspect_certificates(home / ".ap-id/route-certs", now)
    attestations = last_attestations(home / ".ap-id/route-attestation.log", set(certificates), now)
    warnings = []
    if not dependencies.get("local_prerequisites_present"):
        warnings.append("LOCAL_RENEWAL_DEPENDENCY_MISSING")
    if not certificates:
        warnings.append("NO_LOCAL_ROUTE_CERTIFICATES")
    for name, metadata in certificates.items():
        if metadata["status"] != "OK":
            warnings.append(f"ROUTE_CERTIFICATE_{metadata['status']}:{name}")
    for name, metadata in attestations.items():
        if metadata["status"] != "OK":
            warnings.append(f"ROUTE_{metadata['status']}:{name}")
    needed_until = recertification_window_end(certificates, now)
    employee = sessions if sessions is not None else (employee_sessions(home) if needed_until else {})
    warnings.extend(session_warnings(employee, needed_until))
    guards = guards if guards is not None else guard_readiness(guard_urls(home))
    for url, info in sorted(guards.items()):
        if info["status"] != "OK":
            warnings.append(f"GUARD_{info['status']}:{urlparse(url).port}:{info.get('sync_error') or 'not_ready'}")
    return {"checked_at": now.isoformat(), "status": "WARNING" if warnings else "OK",
            "renewal_host": "OWNER_LAPTOP_NOT_ALWAYS_ON", "local_dependencies_present": dependencies.get("local_prerequisites_present") is True,
            "route_certificates": certificates, "route_attestation": attestations, "warnings": warnings,
            "employee_sessions": employee, "guards": guards,
            "employee_sessions_needed_until": needed_until.isoformat() if needed_until else None,
            "source_certificate_live_check": "NOT_PERFORMED", "migration_complete": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    args = parser.parse_args()
    result = check(args.home, datetime.now(timezone.utc))
    print(json.dumps(result, sort_keys=True), flush=True)
    return 1 if result["warnings"] else 0


if __name__ == "__main__":
    sys.exit(main())
