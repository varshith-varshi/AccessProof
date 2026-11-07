#!/usr/bin/env python3
"""Read-only availability observer for the cross-host validation Gateway.

No AWS permissions, employee credentials, signing key or Protect control.
Runs safely on a separate, always-on host and reports dependency loss even
when the laptop-held route and certifier cannot run. THIS IS NOT A SIGNER.
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib import error, request


PUBLIC_CHECKS = {
    "api": "https://api.accessproof.in/health/ready",
    "web": "https://app.accessproof.in/login",
}


def _public_ready(url: str) -> bool:
    opener = request.build_opener(
        request.ProxyHandler({}),
        request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with opener.open(request.Request(url, headers={"User-Agent": "AccessProof-Observer/1.0"}),
                         timeout=6) as response:
            if response.status != 200 or response.geturl() != url:
                return False
            body = response.read(2048)
        if url.endswith("/health/ready"):
            result = json.loads(body)
            return (
                isinstance(result, dict)
                and result.get("status") == "ready"
                and isinstance(result.get("dependencies"), dict)
                and result["dependencies"].get("database") == "ok"
                and result["dependencies"].get("redis") == "ok"
            )
        return bool(body)
    except (OSError, ValueError, error.URLError):
        return False


def _pinned_gateway_ready(ca_file: Path, hostname: str) -> bool:
    """Check loopback reverse tunnel while retaining real DNS-name TLS pinning."""
    if (ca_file.is_symlink() or not ca_file.is_file()
            or not 1 <= ca_file.stat().st_size <= 65536
            or hostname != "ap-gateway.lab.internal"):
        return False
    try:
        context = ssl.create_default_context(cafile=str(ca_file))
        with socket.create_connection(("127.0.0.1", 18443), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as tls:
                tls.settimeout(5)
                tls.sendall(
                    b"GET /health/ready HTTP/1.1\r\nHost: ap-gateway.lab.internal\r\n"
                    b"Connection: close\r\nAccept: application/json\r\n\r\n"
                )
                response = b""
                while len(response) <= 4096:
                    part = tls.recv(min(1024, 4097 - len(response)))
                    if not part:
                        break
                    response += part
        headers, separator, body = response.partition(b"\r\n\r\n")
        if not separator or len(response) > 4096 or not headers.startswith(b"HTTP/1.1 200 "):
            return False
        data = json.loads(body)
        return isinstance(data, dict) and data.get("status") == "ok"
    except (OSError, ValueError, ssl.SSLError):
        return False


def check(ca_file: Path) -> dict[str, object]:
    status = {name: "UP" if _public_ready(url) else "DOWN"
              for name, url in PUBLIC_CHECKS.items()}
    status["gateway_tunnel"] = (
        "UP" if _pinned_gateway_ready(ca_file, "ap-gateway.lab.internal") else "DOWN"
    )
    ok = all(value == "UP" for value in status.values())
    return {
        "schema": "accessproof.independent_route_observer/v1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "overall": "UP" if ok else "DEGRADED",
        "status": status,
        "certificate_signing": "NOT_SUPPORTED_BY_OBSERVER",
        "protect_certification": "NOT_VERIFIED_BY_OBSERVER",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca-file", type=Path, required=True)
    args = parser.parse_args()
    result = check(args.ca_file)
    print(json.dumps(result, separators=(",", ":"), sort_keys=True), flush=True)
    return 0 if result["overall"] == "UP" else 2


if __name__ == "__main__":
    sys.exit(main())
