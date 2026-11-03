#!/usr/bin/env python3
"""Synthetic group / inheritance fixtures on the authorized lab site only.

    create    add the fixtures (idempotent); records ids in a 0600 state file
    verify    print every grant on the fixtures (no content, no tokens)
    teardown  delete the fixture files, subfolder and group

Fixtures (all synthetic, canary-tagged, Alice only):
  * Entra security group  AP-Lab-Group-Finance-Readers  (member: alice)
    file  Synthetic-RAG-Test/group_finance_alice.txt     read: that group only
  * subfolder  Synthetic-RAG-Test/Inherited-Alice        read: alice (direct)
    file  Inherited-Alice/inherited_finance_alice.txt    inherits the folder grant

Existing fixture files (finance_alice, engineering_bob, shared_control) are
never touched. Copied site-group grants are removed from the NEW items so the
only access paths are the ones under test. Group membership uses the operator's
signed-in Azure CLI (delegated); file operations use the AccessProof app,
whose Sites.Selected grant is limited to this site.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ei", HERE / "employee_identity.py")
ei = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ei)

STATE = Path.home() / ".config/accessproof/lab-fixtures.json"
GROUP = "AP-Lab-Group-Finance-Readers"
SUBFOLDER = "Inherited-Alice"
FILES = {
    "group_finance_alice.txt": "ACCESSPROOF_SYNTHETIC_GROUP_FINANCE_20261103_G44 Synthetic group-granted finance test document. "
                               "Readable ONLY through Entra group AP-Lab-Group-Finance-Readers (member: alice). No real data.\n",
    "inherited_finance_alice.txt": "ACCESSPROOF_SYNTHETIC_INHERITED_FINANCE_20261103_H63 Synthetic inherited finance test document. "
                                   "Readable ONLY through the Inherited-Alice folder grant to alice. No real data.\n",
}
G = "https://graph.microsoft.com/v1.0"


def az(*args: str) -> str:
    return subprocess.run(["az", *args], check=True, capture_output=True, text=True).stdout.strip()


def _state() -> dict:
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def _save(state: dict) -> None:
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=1))
    STATE.chmod(0o600)


def _who(p: dict) -> list[str]:
    out = []
    for g in (p.get("grantedToIdentitiesV2") or ([p["grantedToV2"]] if p.get("grantedToV2") else [])):
        for kind in ("user", "group", "siteGroup", "application"):
            if g.get(kind):
                out.append(f"{kind}:{g[kind].get('displayName')}")
    return out


class Lab:
    def __init__(self, http: httpx.Client):
        self.http = http
        self.h = {"Authorization": "Bearer " + ei._app_only_token(http)}
        self.drive, _ = ei.item_refs(http)
        self.folder = self.get(f"/drives/{self.drive}/root:/{ei.FOLDER}")["id"]

    def get(self, path: str) -> dict:
        r = self.http.get(G + path, headers=self.h)
        r.raise_for_status()
        return r.json()

    def perms(self, item: str) -> list[dict]:
        return self.get(f"/drives/{self.drive}/items/{item}/permissions")["value"]

    def upload(self, parent: str, name: str, body: str) -> str:
        r = self.http.put(f"{G}/drives/{self.drive}/items/{parent}:/{name}:/content",
                          headers={**self.h, "Content-Type": "text/plain"}, content=body.encode())
        r.raise_for_status()
        return r.json()["id"]

    def invite(self, item: str, object_id: str) -> None:
        r = self.http.post(f"{G}/drives/{self.drive}/items/{item}/invite", headers=self.h, json={
            "recipients": [{"objectId": object_id}], "roles": ["read"],
            "requireSignIn": True, "sendInvitation": False})
        r.raise_for_status()

    def strip_site_groups(self, item: str) -> list[str]:
        removed = []
        for p in self.perms(item):
            if p.get("inheritedFrom"):
                continue
            if any(w.startswith("siteGroup:") for w in _who(p)):
                self.http.delete(f"{G}/drives/{self.drive}/items/{item}/permissions/{p['id']}", headers=self.h).raise_for_status()
                removed += _who(p)
        return removed


def create(lab: Lab) -> dict:
    st = _state()
    alice = az("ad", "user", "show", "--id", f"alice@{ei.UPN_DOMAIN}", "--query", "id", "-o", "tsv")
    gid = st.get("group_id") or az("ad", "group", "list", "--display-name", GROUP, "--query", "[0].id", "-o", "tsv")
    if not gid:
        gid = az("ad", "group", "create", "--display-name", GROUP, "--mail-nickname", "ap-lab-group-finance-readers",
                 "--description", "AccessProof lab synthetic fixture; delete after validation", "--query", "id", "-o", "tsv")
    if az("ad", "group", "member", "check", "--group", gid, "--member-id", alice, "--query", "value", "-o", "tsv") != "true":
        az("ad", "group", "member", "add", "--group", gid, "--member-id", alice)
    st.update(group_id=gid, alice_oid=alice)
    _save(st)
    time.sleep(10)  # directory propagation before SharePoint resolves the group

    gf = lab.upload(lab.folder, "group_finance_alice.txt", FILES["group_finance_alice.txt"])
    lab.invite(gf, gid)
    st["group_file_id"] = gf
    st["group_file_removed_site_groups"] = lab.strip_site_groups(gf)

    sub = st.get("subfolder_id")
    if not sub:
        r = lab.http.post(f"{G}/drives/{lab.drive}/items/{lab.folder}/children", headers=lab.h, json={
            "name": SUBFOLDER, "folder": {}, "@microsoft.graph.conflictBehavior": "fail"})
        sub = r.json()["id"] if r.status_code == 201 else lab.get(f"/drives/{lab.drive}/root:/{ei.FOLDER}/{SUBFOLDER}")["id"]
    lab.invite(sub, alice)
    st["subfolder_id"] = sub
    st["subfolder_removed_site_groups"] = lab.strip_site_groups(sub)
    st["inherited_file_id"] = lab.upload(sub, "inherited_finance_alice.txt", FILES["inherited_finance_alice.txt"])
    _save(st)
    return st


def verify(lab: Lab) -> dict:
    st = _state()
    out = {}
    for key in ("group_file_id", "subfolder_id", "inherited_file_id"):
        if st.get(key):
            out[key] = [{"roles": p.get("roles"), "inherited": bool(p.get("inheritedFrom")), "who": _who(p)}
                        for p in lab.perms(st[key])]
    if st.get("group_id"):
        out["group_members"] = json.loads(az("ad", "group", "member", "list", "--group", st["group_id"],
                                             "--query", "[].userPrincipalName", "-o", "json"))
    return out


def teardown(lab: Lab) -> dict:
    st = _state()
    done = {}
    for key in ("group_file_id", "subfolder_id"):  # deleting the subfolder deletes its file
        if st.get(key):
            r = lab.http.delete(f"{G}/drives/{lab.drive}/items/{st[key]}", headers=lab.h)
            done[key] = r.status_code
    if st.get("group_id"):
        subprocess.run(["az", "ad", "group", "delete", "--group", st["group_id"]], check=False, capture_output=True)
        done["group_deleted"] = True
    STATE.unlink(missing_ok=True)
    return done


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("action", choices=["create", "verify", "teardown"])
    a = p.parse_args()
    with httpx.Client(timeout=30, trust_env=False) as http:
        lab = Lab(http)
        result = {"create": create, "verify": verify, "teardown": teardown}[a.action](lab)
    print(json.dumps(result, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
