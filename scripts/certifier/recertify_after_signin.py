#!/usr/bin/env python3
"""Wait for both employee sign-ins, then start the route attestation service once.

    python scripts/certifier/recertify_after_signin.py [--timeout-min 35] [--margin-hours 3]

Polls only the non-secret ``claims``/``session`` socket queries (never tokens).
When both sessions report a wall-clock end beyond the margin, it starts
``accessproof-route-attestation.service``; that run re-certifies any route within
its --opportunistic-days window. Nothing is started if sign-in does not complete.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.certifier.remote_route_attestation import sessions_cover_full_run  # noqa: E402
from scripts.certifier.renewal_watchdog import employee_sessions  # noqa: E402

UNIT = "accessproof-route-attestation.service"


def wait_and_start(timeout_s: float, margin_hours: float, *, poll=lambda: employee_sessions(Path.home()),
                   start=lambda: subprocess.run(["systemctl", "--user", "start", "--no-block", UNIT], check=False).returncode,
                   sleep=time.sleep, clock=time.monotonic) -> str:
    end = clock() + timeout_s
    while clock() < end:
        if sessions_cover_full_run(margin_hours, poll()):
            return "STARTED" if start() == 0 else "START_FAILED"
        sleep(15)
    return "SIGNIN_NOT_COMPLETED"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--timeout-min", type=float, default=35)
    p.add_argument("--margin-hours", type=float, default=3.0)
    a = p.parse_args()
    outcome = wait_and_start(a.timeout_min * 60, a.margin_hours)
    print(f"RECERTIFY_AFTER_SIGNIN {outcome}", flush=True)
    return 0 if outcome == "STARTED" else 1


if __name__ == "__main__":
    sys.exit(main())
