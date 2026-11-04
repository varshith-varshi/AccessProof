#!/usr/bin/env python3
"""Live SharePoint revocation trials A-D/E with the seven-timestamp scheme.

    python scripts/live/revocation_trial.py --trial A --socket SOCK --out rev-A.json [--execute]

Without --execute it only prints the plan and the current state (read-only).

Trials (synthetic lab fixtures only; Alice only):
  A  direct grant      finance_alice.txt          remove Alice's direct read grant
  B  group membership  group_finance_alice.txt    remove Alice from AP-Lab-Group-Finance-Readers
  C  inherited grant   inherited_finance_alice.txt remove Alice's grant on folder Inherited-Alice
  D  deletion          delete_canary_alice.txt    created for the trial, then deleted
E (restoration) runs automatically after A-C: the original grant is restored
and the same timestamps are recorded until Alice is ALLOWED again.

Timestamps (UTC):
  t0 source change initiated     t1 source change confirmed (Graph + Alice's own delegated probe)
  t2 AccessProof change detected (production effective access, read-only SSM)
  t3 authorization revision updated (production Guard registration, read-only SSM)
  t4 Guard acknowledged          (lab Guard cache installed that revision)
  t5 first Guard denial          t6 stable denial (5 consecutive denials spanning >= 60 s)

Restoration is attempted in `finally`; a 0600 recovery file records how to
undo an interrupted trial (`--restore-only`). Never prints tokens or content.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ei = _load("employee_identity")
fx = _load("sharepoint_fixtures")
sem = _load("sharepoint_effective_matrix")


def sharepoint_effective_view(document: str, actor: str = "alice") -> bool:
    """SharePoint's own verdict (GetUserEffectivePermissions) for this employee."""
    import asyncio
    people = json.loads((Path.home() / ".config/accessproof/sharepoint-rest-validation/synthetic-verified-employees.json").read_text())
    items = sem.list_items()
    if document not in items:
        return False  # deleted: nothing to view
    saved = sem.EXPECTED
    try:
        sem.EXPECTED = {actor: {document: True}}
        return bool(asyncio.run(sem.effective(items, people))[0]["sharepoint_effective_view"])
    finally:
        sem.EXPECTED = saved

ORG = "48ee8c86-d4d8-4cde-b00b-bc779f965f4f"
SOURCE = "2fa9562b-b765-4098-bebf-222ea53ec667"
APP = "sharepoint-rag-staging"
GUARD_ID = "102691c8-54d7-44d7-b1b1-bc40c9f335f4"
INSTANCE = "i-0c11427d4d9c1b438"
GUARD_URL = "http://127.0.0.1:8080"
GUARD_CONTAINER = "accessproof-guard"
RECOVERY = Path.home() / ".config/accessproof/revocation-recovery.json"

import importlib.util as _ilu  # noqa: E402
_ps = _ilu.spec_from_file_location("_ap_profile", Path(__file__).resolve().parent / "_profile.py")
_pm = _ilu.module_from_spec(_ps); _ps.loader.exec_module(_pm)
PROFILE = _pm.apply("revocation_trial", globals())
TRIALS = {"A": "finance_alice.txt", "B": "group_finance_alice.txt",
          "C": "inherited_finance_alice.txt", "D": "delete_canary_alice.txt"}
G = fx.G


# Which served token the Guard receives: "api_token" (delegated API access token,
# the production contract) or "id_token" (interim, before the API scope is consented).
TOKEN_KIND = os.environ.get("AP_TOKEN_KIND", "api_token")
assert TOKEN_KIND in {"api_token", "id_token"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ssm_sql(sql: str) -> str:
    """Read-only query on production (psql -Atc), via AWS SSM."""
    cmd = ("docker exec accessproof-db-1 psql -U accessproof -d accessproof -Atc "
           + json.dumps(sql).replace("$", "\\$"))
    cid = subprocess.run(["aws", "ssm", "send-command", "--region", "eu-north-1", "--instance-ids", INSTANCE,
                          "--document-name", "AWS-RunShellScript", "--comment", "Read-only: revocation trial poll",
                          "--parameters", json.dumps({"commands": [cmd]}), "--query", "Command.CommandId",
                          "--output", "text"], check=True, capture_output=True, text=True).stdout.strip()
    for _ in range(40):
        time.sleep(1.5)
        r = subprocess.run(["aws", "ssm", "get-command-invocation", "--region", "eu-north-1", "--command-id", cid,
                            "--instance-id", INSTANCE, "--query", "[Status,StandardOutputContent]", "--output", "json"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            status, out = json.loads(r.stdout)
            if status in ("Success", "Failed"):
                return out.strip()
    raise RuntimeError("SSM_TIMEOUT")


def ap_effective_allows(resource_name: str) -> bool:
    out = ssm_sql(
        "select count(*) from guard_effective_access e join guard_resources r on r.id=e.resource_id "
        "join guard_subjects s on s.id=e.subject_id where e.organization_id='" + ORG + "' and e.source_id='"
        + SOURCE + "' and s.display_name='alice' and e.decision='allow' and r.metadata_json::json->>'name'='"
        + resource_name + "'")
    return out.strip() not in ("", "0")


def ap_revision() -> int | None:
    out = ssm_sql("select active_authorization_revisions_json from guard_registrations where id='" + GUARD_ID + "'")
    try:
        return int(json.loads(out)[APP]["revision"])
    except (ValueError, KeyError, TypeError):
        return None


def guard_revision() -> int | None:
    r = subprocess.run(["docker", "exec", GUARD_CONTAINER, "python", "-c",
                        "import sqlite3;c=sqlite3.connect('file:/var/lib/accessproof-guard/policy.db?mode=ro',uri=True);"
                        f"r=c.execute(\"select revision from authorization_revisions where application_id='{APP}'\").fetchone();"
                        "print(r[0] if r else '')"], capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip().isdigit() else None


def indexed_version(resource_id: str) -> str | None:
    """The document version the lab RAG indexed (what the Gateway sends since r31)."""
    code = ("import sqlite3;c=sqlite3.connect('file:/data/index.db?mode=ro',uri=True);"
            f"r=c.execute(\"select max(version) from chunks where doc_id='{resource_id}'\").fetchone();print(r[0] or '')")
    out = subprocess.run(["docker", "exec", "sharepoint-rag-lab-rag-1", "python", "-c", code],
                         capture_output=True, text=True).stdout.strip()
    return out or None


def guard_decision(id_token: str, resource_id: str) -> str:
    """Layer 1 decision for ONE resource, exactly as the Gateway asks it
    (including the indexed content version the Gateway forwards)."""
    ref = {"source_id": SOURCE, "resource_id": resource_id}
    version = indexed_version(resource_id)
    if version:
        ref["content_version"] = version
    try:
        r = httpx.post(f"{GUARD_URL}/guard/v1/filter-resources", timeout=10,
                       headers={"Authorization": f"Bearer {id_token}"},
                       json={"application_id": APP, "request_id": f"rev-{time.time_ns()}",
                             "resources": [ref]})
    except httpx.HTTPError:
        return "ERROR"
    if r.status_code != 200:
        return f"HTTP_{r.status_code}:{r.json().get('detail', '') if r.content else ''}"
    allowed = {x["resource_id"] for x in r.json().get("allowed", [])}
    return "ALLOW" if resource_id in allowed else "DENY"


class Trial:
    def __init__(self, letter: str, sock: str):
        self.letter, self.sock, self.doc = letter, sock, TRIALS[letter]
        self.http = httpx.Client(timeout=30, trust_env=False)
        self.lab = fx.Lab(self.http)
        self.state = fx._state()
        self.drive = self.lab.drive
        self.alice_oid = self.state.get("alice_oid") or fx.az("ad", "user", "show", "--id", f"alice@{ei.UPN_DOMAIN}", "--query", "id", "-o", "tsv")

    # --- item / provider helpers ----------------------------------------------------------
    def item_id(self) -> str:
        _, items = ei.item_refs(self.http)
        if self.doc in items:
            return items[self.doc]
        if self.letter == "C":
            return self.state["inherited_file_id"]
        raise RuntimeError("ITEM_MISSING")

    def provider_resource(self) -> str:
        """AccessProof resource ids are the provider item ids."""
        return self.item_id()

    def alice_direct(self, item: str) -> str:
        return ei.delegated_decision(self.http, self.drive, item, ei.fetch(self.sock, "access_token"))[0]

    def _grant_on(self, item: str) -> dict | None:
        for p in self.lab.perms(item):
            if any(w == "user:alice" for w in fx._who(p)) and "read" in p.get("roles", []):
                return p
        return None

    # --- mutations ------------------------------------------------------------------------
    def revoke(self) -> dict:
        rec = {"trial": self.letter, "document": self.doc, "at": now()}
        if self.letter == "A":
            item = self.item_id()
            p = self._grant_on(item)
            if p is None:
                raise RuntimeError("ALICE_DIRECT_GRANT_NOT_FOUND")
            rec.update(kind="direct", item=item)
            self._record(rec)
            self.http.delete(f"{G}/drives/{self.drive}/items/{item}/permissions/{p['id']}", headers=self.lab.h).raise_for_status()
        elif self.letter == "B":
            rec.update(kind="group", group=self.state["group_id"])
            self._record(rec)
            fx.az("ad", "group", "member", "remove", "--group", self.state["group_id"], "--member-id", self.alice_oid)
        elif self.letter == "C":
            folder = self.state["subfolder_id"]
            p = self._grant_on(folder)
            if p is None:
                raise RuntimeError("ALICE_FOLDER_GRANT_NOT_FOUND")
            rec.update(kind="inherited", folder=folder)
            self._record(rec)
            self.http.delete(f"{G}/drives/{self.drive}/items/{folder}/permissions/{p['id']}", headers=self.lab.h).raise_for_status()
        elif self.letter == "D":
            item = self.item_id()
            rec.update(kind="delete", item=item)
            self._record(rec)
            self.http.delete(f"{G}/drives/{self.drive}/items/{item}", headers=self.lab.h).raise_for_status()
        return rec

    def restore(self) -> None:
        rec = json.loads(RECOVERY.read_text()) if RECOVERY.exists() else None
        if not rec:
            return
        if rec["kind"] == "direct":
            self.lab.invite(rec["item"], self.alice_oid)
        elif rec["kind"] == "group":
            fx.az("ad", "group", "member", "add", "--group", rec["group"], "--member-id", self.alice_oid)
        elif rec["kind"] == "inherited":
            self.lab.invite(rec["folder"], self.alice_oid)
            self.lab.strip_site_groups(rec["folder"])
        RECOVERY.unlink(missing_ok=True)

    def _record(self, rec: dict) -> None:
        RECOVERY.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        RECOVERY.write_text(json.dumps(rec))
        RECOVERY.chmod(0o600)

    # --- measurement ----------------------------------------------------------------------
    def measure(self, item: str, want: str, t0: float, budget_s: int, phase: str) -> dict:
        """Poll until Guard decisions are stably `want` (DENY after revoke, ALLOW after restore)."""
        provider_ok = "DENY" if want == "DENY" else "ALLOW"
        ts: dict[str, str | None] = {k: None for k in ("t1_source_confirmed", "t2n_notification_received", "t2_accessproof_detected",
                                                         "t3_revision_updated", "t4_guard_acknowledged",
                                                         "t5_first_decision", "t6_stable_decision")}
        rev_before = ap_revision()
        streak: list[float] = []
        decisions = []
        end = time.monotonic() + budget_s
        while time.monotonic() < end and ts["t6_stable_decision"] is None:
            if ts["t1_source_confirmed"] is None:
                # SharePoint's own effective-permission verdict for Alice (not a
                # scope-limited delegated read, which could look like DENY: D-21).
                grant_holder = {"A": item, "C": self.state.get("subfolder_id")}.get(self.letter)
                listed = self._grant_on(grant_holder) is not None if grant_holder else None
                view = sharepoint_effective_view(self.doc)
                if ("ALLOW" if view else "DENY") == provider_ok and listed in (None, want == "ALLOW"):
                    ts["t1_source_confirmed"] = now()
            if ts["t2n_notification_received"] is None:
                # r35+: first AUTHENTICATED Microsoft notification journaled for
                # this source after t0 (provider-side delivery, measured separately).
                first = ssm_sql("select coalesce(min(received_at)::text,'') from provider_event_journal where source_id='"
                                + SOURCE + "' and provider='microsoft365' and received_at >= to_timestamp("
                                + str(t0) + ")")
                if first.strip():
                    ts["t2n_notification_received"] = first.strip().replace(" ", "T")
            if ts["t2_accessproof_detected"] is None and ap_effective_allows(self.doc) == (want == "ALLOW"):
                ts["t2_accessproof_detected"] = now()
            rev = ap_revision()
            if ts["t3_revision_updated"] is None and rev is not None and rev_before is not None and rev != rev_before:
                ts["t3_revision_updated"] = now()
            if ts["t3_revision_updated"] and ts["t4_guard_acknowledged"] is None and guard_revision() == rev:
                ts["t4_guard_acknowledged"] = now()
            d = guard_decision(ei.fetch(self.sock, TOKEN_KIND), self.provider_resource() if self.letter != "D" else item)
            decisions.append({"at": now(), "decision": d})
            if d == want:
                ts["t5_first_decision"] = ts["t5_first_decision"] or now()
                streak.append(time.monotonic())
                if len(streak) >= 5 and streak[-1] - streak[0] >= 60:
                    ts["t6_stable_decision"] = now()
            else:
                streak = []
            time.sleep(5)
        start = datetime.fromtimestamp(t0, timezone.utc)
        lat = {k: (round((datetime.fromisoformat(v) - start).total_seconds(), 1) if v else None) for k, v in ts.items()}
        return {"phase": phase, "want": want, "t0_initiated": start.isoformat(), **ts,
                "latency_seconds_from_t0": lat, "decisions": decisions[-40:],
                "completed": ts["t6_stable_decision"] is not None}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--trial", choices=sorted(TRIALS), required=True)
    p.add_argument("--socket", required=True, help="alice token socket from employee_identity.py serve")
    p.add_argument("--out", required=True)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--budget-seconds", type=int, default=2400)
    p.add_argument("--restore-only", action="store_true")
    p.add_argument("--route", action="store_true",
                   help="also record E2E-07/08/09 on the real protected route (trial A only)")
    a = p.parse_args()
    if a.route and a.trial != "A":
        p.error("--route is defined for trial A (finance_alice.txt)")
    t = Trial(a.trial, a.socket)
    if a.restore_only:
        t.restore()
        print("restored" if not RECOVERY.exists() else "RESTORE FAILED")
        return 0
    if RECOVERY.exists():
        print("A previous trial was interrupted; run --restore-only first.", file=sys.stderr)
        return 2
    if a.trial == "D" and a.execute:
        t.lab.upload(t.lab.folder, TRIALS["D"], "ACCESSPROOF_SYNTHETIC_DELETE_CANARY_20261103_D17 Synthetic deletion test. No real data.\n")
        t.lab.invite(t.item_id(), t.alice_oid)
        print("created deletion canary; waiting for AccessProof to sync it (ALLOW)")
        pre = t.measure(t.item_id(), "ALLOW", time.time(), a.budget_seconds, "pre-delete-sync")
        if not pre["completed"]:
            print("deletion canary never became ALLOW; aborting", file=sys.stderr)
            return 1
    item = t.item_id()
    baseline = {"sharepoint_effective_view": sharepoint_effective_view(t.doc),
                "guard": guard_decision(ei.fetch(a.socket, TOKEN_KIND), item),
                "accessproof_allows": ap_effective_allows(t.doc), "revision": ap_revision()}
    print(json.dumps({"trial": a.trial, "document": t.doc, "baseline": baseline, "execute": a.execute}))
    if not a.execute:
        return 0
    if baseline["guard"] != "ALLOW" or not baseline["sharepoint_effective_view"]:
        print("baseline is not ALLOW through the Guard; refusing to revoke", file=sys.stderr)
        return 1
    result = {"schema": "accessproof.revocation_trial/v1", "trial": a.trial, "document": t.doc,
              "item_id": item, "baseline": baseline, "phases": []}
    def save() -> str:
        # Written after every phase and on any failure: a lost token session or
        # crash must never discard what was already observed.
        body = json.dumps(result, indent=1)
        Path(a.out).write_text(body)
        return body
    probe = None
    if a.route:
        rr = _load("route_revocation")
        probe = rr.RouteProbe(lambda: ei.fetch(a.socket, TOKEN_KIND), t.doc)
        probe.before_revoke()
        result["route"] = probe.results
        save()
        if probe.results["E2E-08-pre"]["status"] != "PASS":
            print("route baseline is not ALLOW/uncached; refusing to revoke", file=sys.stderr)
            return 1
    try:
        t0 = time.time()
        result["revoke"] = t.revoke()
        save()
        if probe:
            probe.start_inflight()
        try:
            result["phases"].append(t.measure(item, "DENY", t0, a.budget_seconds, "revoke"))
        finally:
            if probe:
                probe.stop_inflight(result["phases"][-1] if result["phases"] else None)
                save()
        if probe and result["phases"][-1]["completed"]:
            probe.after_stable_denial()
        save()
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
        save()
        raise
    finally:
        if a.trial != "D":
            t0 = time.time()
            t.restore()
            result["restored_at"] = now()
            save()
            try:
                result["phases"].append(t.measure(item, "ALLOW", t0, a.budget_seconds, "restore (E)"))
            except Exception as exc:
                result["restore_measure_error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
            save()
    if a.trial == "D":
        RECOVERY.unlink(missing_ok=True)  # a deletion has nothing to restore
    body = save()
    Path(a.out).write_text(body)
    print(json.dumps({"trial": a.trial, "sha256": hashlib.sha256(body.encode()).hexdigest(),
                      "phases": [(ph["phase"], ph["completed"], ph["latency_seconds_from_t0"]) for ph in result["phases"]]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
