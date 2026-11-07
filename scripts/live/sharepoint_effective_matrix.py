#!/usr/bin/env python3
"""SharePoint's OWN effective-permission verdict (ListItem.GetUserEffectivePermissions)
for each synthetic document and employee. Certificate-authenticated app-only
SharePoint REST on the lab site (Sites.Selected fullcontrol). The claims login
is used only to ask SharePoint about that principal, never as proof of identity;
it is tied to the immutable oid by the verified-employees record.

    python scripts/live/sharepoint_effective_matrix.py --out matrix.json
"""
from __future__ import annotations

import argparse
import importlib.util as _ilu
import asyncio
import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from connectors.microsoft365.sharepoint_effective import SharePointEffectiveAccessProbe  # noqa: E402
from packages.auth.microsoft_certificate import sharepoint_rest_app_token  # noqa: E402

spec = importlib.util.spec_from_file_location("ei", Path(__file__).with_name("employee_identity.py"))
ei = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ei)

CFG = Path.home() / ".config/accessproof"
ORG = "48ee8c86-d4d8-4cde-b00b-bc779f965f4f"
SOURCE = "2fa9562b-b765-4098-bebf-222ea53ec667"
SITE = "https://neuralmatrix093.sharepoint.com/sites/AccessProof-Validation-20261027"
EXPECTED = {
    "alice": {"finance_alice.txt": True, "engineering_bob.txt": False, "shared_control.txt": True,
              "group_finance_alice.txt": True, "inherited_finance_alice.txt": True},
    "bob": {"finance_alice.txt": False, "engineering_bob.txt": True, "shared_control.txt": True,
            "group_finance_alice.txt": False, "inherited_finance_alice.txt": False},
}

PEOPLE_FILE = CFG / "sharepoint-rest-validation/synthetic-verified-employees.json"
SHAREPOINT_CERT_DIR = CFG / "sharepoint-rest-validation"
GRAPH_REGISTRATION = CFG / "entra-app-registration.json"
FIXTURE_STATE = CFG / "lab-fixtures.json"
_ps = _ilu.spec_from_file_location("_ap_effective_profile", Path(__file__).with_name("_profile.py"))
_pm = _ilu.module_from_spec(_ps)
_ps.loader.exec_module(_pm)
PROFILE = _pm.apply("sharepoint_effective_matrix", globals())


def list_items() -> dict[str, tuple[str, int]]:
    """document -> (list guid, list item id), resolved with the AccessProof app."""
    with httpx.Client(timeout=30, trust_env=False) as http:
        h = {"Authorization": "Bearer " + ei._app_only_token(http)}
        drive, items = ei.item_refs(http)
        st = json.loads(Path(FIXTURE_STATE).read_text())
        items["inherited_finance_alice.txt"] = st["inherited_file_id"]
        out = {}
        for name, iid in items.items():
            ids = http.get(f"https://graph.microsoft.com/v1.0/drives/{drive}/items/{iid}?$select=sharepointIds",
                           headers=h).json()["sharepointIds"]
            out[name] = (ids["listId"], int(ids["listItemId"]))
        return out


async def effective(items: dict[str, tuple[str, int]], people: dict) -> list[dict]:
    reg = json.loads(Path(GRAPH_REGISTRATION).read_text())
    private = Path(SHAREPOINT_CERT_DIR)
    async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
        token = await sharepoint_rest_app_token(
            tenant_id=reg["home_tenant"], client_id=reg["client_id"], sharepoint_host=__import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(SITE).hostname,
            private_key_file=private / "client-private.pem", certificate_der_file=private / "client-public.cer",
            client=client)
        probe = SharePointEffectiveAccessProbe(site_url=SITE, sharepoint_access_token=token, client=client)
        rows = []
        for actor, docs in EXPECTED.items():
            for doc, want in docs.items():
                if doc not in items:
                    continue
                list_id, item_id = items[doc]
                got = await probe.can_view_item(list_id=list_id, item_id=item_id,
                                                verified_login_name=people[actor]["sharepoint_login_name"])
                rows.append({"actor": actor, "object_id": people[actor]["object_id"], "document": doc,
                             "list_item_id": item_id, "expected_view": want, "sharepoint_effective_view": got,
                             "pass": got == want, "at": datetime.now(timezone.utc).isoformat()})
        return rows


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True)
    a = p.parse_args()
    people = json.loads(Path(PEOPLE_FILE).read_text())
    rows = asyncio.run(effective(list_items(), people))
    body = json.dumps({"schema": "accessproof.sharepoint_effective_matrix/v1",
                       "organization_id": ORG, "source_id": SOURCE, "tenant_id": ei.TENANT, "site_url": SITE,
                       "method": "SharePoint REST ListItem.GetUserEffectivePermissions (app-only certificate)",
                       "results": rows, "pass": all(r["pass"] for r in rows)}, indent=1)
    Path(a.out).write_text(body)
    for r in rows:
        print(f"{r['actor']:5s} {r['document']:28s} expected {'VIEW' if r['expected_view'] else 'NONE':4s} "
              f"sharepoint {'VIEW' if r['sharepoint_effective_view'] else 'NONE':4s} {'PASS' if r['pass'] else 'FAIL'}")
    print("sha256", hashlib.sha256(body.encode()).hexdigest())
    return 0 if all(r["pass"] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
