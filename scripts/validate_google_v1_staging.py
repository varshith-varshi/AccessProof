#!/usr/bin/env python3
"""Read-only, privacy-limited diagnostics for a Google Workspace + Drive V1 staging stack.

Not certification: no mutations, no provider-user oracle, no customer RAG route.
An operator must separately execute the authorized live validation matrix.
Do not pass session credentials as command-line arguments.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        # Requests with Authorization must NEVER follow a provider-controlled
        # redirect to another host, even if its scheme is HTTPS.
        return None


def get_json(url: str, token: str, organization_id: str) -> tuple[int, object]:
    request = Request(url, headers={
        "Authorization": f"Bearer {token}",
        "X-Organization-ID": organization_id,
        "Accept": "application/json",
    })
    try:
        with build_opener(NoRedirect).open(request, timeout=15) as response:
            raw = response.read(1_000_001)
            if len(raw) > 1_000_000:
                return 0, {"code": "RESPONSE_TOO_LARGE"}
            return response.status, json.loads(raw)
    except HTTPError as exc:
        return exc.code, {"code": "UPSTREAM_HTTP_FAILURE"}
    except (URLError, TimeoutError, ValueError, UnicodeDecodeError) as exc:
        return 0, {"code": type(exc).__name__}


def summarize(name: str, body: object) -> dict[str, object]:
    if not isinstance(body, list):
        return {"record_count": 0, "readable": False}
    if name == "sources":
        return {
            "record_count": len(body),
            "google_only": all(
                isinstance(item, dict) and item.get("provider") == "google-drive"
                for item in body
            ),
            "directory_fresh_count": sum(
                bool(isinstance(item, dict) and (item.get("directory_sync") or {}).get("fresh"))
                for item in body
            ),
            "acl_fresh_count": sum(
                bool(isinstance(item, dict) and (item.get("acl_sync") or {}).get("fresh"))
                for item in body
            ),
            "readable": True,
        }
    return {
        "record_count": len(body),
        "readable": True,
        "healthy_count": sum(
            bool(isinstance(item, dict) and item.get("health") == "healthy")
            for item in body
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True, help="HTTPS staging API origin")
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--token-stdin", action="store_true", help="Read session token from stdin")
    args = parser.parse_args()
    parsed = urlsplit(args.api_url)
    if (parsed.scheme != "https" or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"}):
        parser.error("--api-url must be a trusted HTTPS origin without credentials, path or query")
    token = sys.stdin.readline().strip() if args.token_stdin else os.environ.get("ACCESSPROOF_STAGING_SESSION_TOKEN", "").strip()
    if not token or any(char.isspace() for char in token) or len(token) > 4096:
        parser.error("Provide a short-lived token through --token-stdin or ACCESSPROOF_STAGING_SESSION_TOKEN")

    base = args.api_url.rstrip("/") + "/api/v1"
    failed = False
    for name, path in (("sources", "/current/sources"), ("guards", "/guards")):
        status, body = get_json(base + path, token, args.organization_id)
        ok = status == 200 and isinstance(body, list)
        failed |= not ok
        # Deliberately never print response records: they can contain customer
        # folder identifiers and operational metadata.
        print(json.dumps({"check": name, "ok": ok, "status": status, **summarize(name, body)}, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
