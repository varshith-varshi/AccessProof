"""Run the Gateway with its own TLS (remote exposure).

    python -m apps.gateway.accessproof_gateway.serve

Env: ACCESSPROOF_GATEWAY_TLS_CERT_FILE, ACCESSPROOF_GATEWAY_TLS_KEY_FILE (required
unless ACCESSPROOF_GATEWAY_TLS_TERMINATION=proxy), optional
ACCESSPROOF_GATEWAY_TLS_CLIENT_CA_FILE to REQUIRE client certificates (mTLS),
ACCESSPROOF_GATEWAY_LISTEN_PORT (default 8443). TLS 1.2 is the minimum.
"""
from __future__ import annotations

import os
import ssl

import uvicorn


def main() -> None:
    cert, key = os.getenv("ACCESSPROOF_GATEWAY_TLS_CERT_FILE", ""), os.getenv("ACCESSPROOF_GATEWAY_TLS_KEY_FILE", "")
    client_ca = os.getenv("ACCESSPROOF_GATEWAY_TLS_CLIENT_CA_FILE", "")
    port = int(os.getenv("ACCESSPROOF_GATEWAY_LISTEN_PORT", "8443"))
    kwargs: dict = {}
    if os.getenv("ACCESSPROOF_GATEWAY_TLS_TERMINATION", "").lower() != "proxy":
        if not (cert and key):
            raise SystemExit("TLS certificate and key are required (or ACCESSPROOF_GATEWAY_TLS_TERMINATION=proxy)")
        kwargs.update(ssl_certfile=cert, ssl_keyfile=key)
        if client_ca:
            kwargs.update(ssl_ca_certs=client_ca, ssl_cert_reqs=ssl.CERT_REQUIRED)
    uvicorn.run("apps.gateway.accessproof_gateway.app:create_app", factory=True, host="0.0.0.0", port=port,
                proxy_headers=False, server_header=False, date_header=False, **kwargs)


if __name__ == "__main__":
    main()
