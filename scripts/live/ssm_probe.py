#!/usr/bin/env python3
"""--rag-exec adapter for a REMOTE RAG host reached through the restricted probe document.

    remote_route_certification.py ... --rag-exec "python3 scripts/live/ssm_probe.py"

The certifier passes ``-c CODE`` plus a JSON payload on stdin. Only the two FIXED
probe programs of remote_route_certification.py are accepted; they are executed by
the AccessProof-Certifier-RagHostProbe document (pinned to the staging instance),
never as arbitrary code.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "certifier"))
import ssm_ops  # noqa: E402


def _probe_code(name: str) -> str:
    src = (HERE / "remote_route_certification.py").read_text()
    start = src.index(f"{name} = r'''") + len(f"{name} = r'''")
    return src[start:src.index("'''", start)]


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] != "-c":
        raise SystemExit("usage: ssm_probe.py -c CODE")
    code, payload = sys.argv[2], json.loads(sys.stdin.read() or "{}")
    if code == _probe_code("_BYPASS"):
        targets = ",".join(f"{h}:{p}" for h, p in payload["targets"])
        print(ssm_ops.rag_host_probe("bypass", targets=targets))
    elif code == _probe_code("_GW_UNSIGNED"):
        print(ssm_ops.rag_host_probe("gateway_unsigned", gatewayUrl=payload["gw"]))
    else:
        raise SystemExit("PROBE_NOT_ALLOWED")      # anything but the two fixed probes is refused
    return 0


if __name__ == "__main__":
    sys.exit(main())
