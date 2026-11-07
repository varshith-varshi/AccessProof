"""Read-only helper to find the SharePoint site ID and document-library drive ID.
Requires the same tenant-approved scoped Entra application as the ingester.
"""
from __future__ import annotations

import argparse
import os
from urllib.parse import urlsplit, quote

import httpx


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--site-url", required=True, help="e.g. https://tenant.sharepoint.com/sites/Lab")
    args = parser.parse_args()
    site = urlsplit(args.site_url)
    hostname = (site.hostname or "").lower()
    if (site.scheme != "https" or not hostname.endswith(".sharepoint.com")
            or site.username or site.password or site.port not in (None, 443)
            or site.query or site.fragment or not site.path.startswith("/sites/")):
        raise SystemExit("Invalid SharePoint site URL; supply an exact HTTPS /sites/... URL")
    needed = ["SHAREPOINT_TENANT_ID", "SHAREPOINT_CLIENT_ID", "SHAREPOINT_CLIENT_SECRET"]
    if any(not os.getenv(k) for k in needed):
        raise SystemExit("Missing SharePoint Entra application variables: " + ", ".join(needed))
    with httpx.Client(timeout=20, follow_redirects=False, trust_env=False) as client:
        t = client.post(
            f"https://login.microsoftonline.com/{quote(os.environ['SHAREPOINT_TENANT_ID'], safe='')}/oauth2/v2.0/token",
            data={"client_id": os.environ["SHAREPOINT_CLIENT_ID"],
                  "client_secret": os.environ["SHAREPOINT_CLIENT_SECRET"],
                  "scope": "https://graph.microsoft.com/.default",
                  "grant_type": "client_credentials"},
        )
        if t.status_code != 200:
            raise SystemExit("Entra app authentication failed; inspect tenant ID and consent")
        token = t.json().get("access_token")
        if not token:
            raise SystemExit("Entra returned no token")
        headers = {"Authorization": "Bearer " + token}
        ref = client.get("https://graph.microsoft.com/v1.0/sites/" + hostname +
                         ":" + site.path.rstrip("/"), headers=headers)
        if ref.status_code != 200:
            raise SystemExit("Graph site lookup failed; verify Sites.Selected assignment")
        site_id = ref.json().get("id")
        if not site_id:
            raise SystemExit("Graph site ID missing")
        drives = client.get("https://graph.microsoft.com/v1.0/sites/" +
                            quote(site_id, safe="") + "/drives", headers=headers)
        if drives.status_code != 200:
            raise SystemExit("Graph library discovery failed; verify app's site read grant")
        print("SHAREPOINT_SITE_ID=" + site_id)
        for drive in drives.json().get("value", []):
            if not isinstance(drive, dict):
                continue
            print("DOCUMENT_LIBRARY_NAME=" + str(drive.get("name", "")))
            print("SHAREPOINT_DRIVE_ID=" + str(drive.get("id", "")))


if __name__ == "__main__":
    main()
