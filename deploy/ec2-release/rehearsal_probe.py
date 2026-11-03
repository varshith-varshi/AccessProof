"""Release-rehearsal HTTP probe — runs INSIDE the api container (stdlib only).

    docker compose exec -T -e PROBE_MODE=seed|probe -e PROBE_PASSWORD=... api python - < rehearsal_probe.py

* ``seed``  — signs up two synthetic tenants (alpha, beta) through the real
  signup route. Staging only: the operator then marks the synthetic emails
  verified with SQL, because staging has no mailbox.
* ``probe`` — login, tenant reads, writes, cross-tenant refusal, route
  presence, and two release-specific behaviours:
    - RT-03: a TOTP code accepted once must be rejected on replay;
    - RT-04: a JSON body sent without ``Content-Type: application/json``.
  Release-specific checks are reported as observations with the release's
  expected value, so the same probe can run before and after an upgrade.

Prints one JSON document. Never prints passwords, session tokens or TOTP
secrets. Never use against production tenants.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8000"
HOST = os.environ.get("PROBE_HOST", "api.accessproof.in")
PW = os.environ["PROBE_PASSWORD"]
A = "alpha-owner@rehearsal.accessproof.in"
B = "beta-owner@rehearsal.accessproof.in"
EXPECT_RT03 = os.environ.get("PROBE_EXPECT_RT03", "fixed")  # fixed | unfixed


def call(method, path, body=None, token=None, org=None, content_type="application/json"):
    data = None if body is None else json.dumps(body).encode()
    headers = {"Host": HOST}
    if data is not None and content_type:
        headers["Content-Type"] = content_type
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if org:
        headers["X-Organization-ID"] = org
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, None


def totp(secret_b32, step):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return f"{(struct.unpack('>I', mac[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


results = {}


def check(name, ok, detail):
    results[name] = {"pass": bool(ok), "detail": detail}


def observe(name, value, expected):
    results[name] = {"observed": value, "expected_for_release": expected, "pass": value == expected}


mode = os.environ.get("PROBE_MODE", "probe")
if mode == "seed":
    out = {}
    for email, org in ((A, "Rehearsal Alpha"), (B, "Rehearsal Beta")):
        st, body = call("POST", "/api/v1/auth/signup", {"email": email, "password": PW, "organization_name": org})
        out[email] = {"status": st, "organization_id": (body or {}).get("organization_id")}
    print(json.dumps(out))
    raise SystemExit(0)

st_a, la = call("POST", "/api/v1/auth/login", {"email": A, "password": PW})
st_b, lb = call("POST", "/api/v1/auth/login", {"email": B, "password": PW})
check("alpha:login", st_a == 200, st_a)
check("beta:login", st_b == 200, st_b)
ta, oa = la["session_token"], la["organizations"][0]["id"]
tb, ob = lb["session_token"], lb["organizations"][0]["id"]

for path in (
    "/api/v1/auth/me", "/api/v1/organization", "/api/v1/current/sources",
    "/api/v1/current/ai-applications", "/api/v1/guards",
    "/api/v1/current/protection/overview", "/api/v1/audit", "/api/v1/current/dashboard",
):
    st, _ = call("GET", path, token=ta, org=oa)
    check(f"GET {path}", st == 200, st)

st, _ = call("PATCH", "/api/v1/organization", {"name": f"Rehearsal Alpha {int(time.time())}"}, token=ta, org=oa)
check("write: rename workspace", st == 200, st)
st, g = call("POST", "/api/v1/guards", {"name": f"rehearsal-guard-{int(time.time())}"}, token=ta, org=oa)
check("write: create guard", st == 201, st)
guard_id = (g or {}).get("id")

st, _ = call("GET", "/api/v1/organization", token=ta, org=ob)
check("cross-tenant read refused", st == 403, st)
st, _ = call("PATCH", "/api/v1/organization", {"name": "hijacked"}, token=ta, org=ob)
check("cross-tenant write refused", st == 403, st)
if guard_id:
    st, _ = call("GET", f"/api/v1/guards/{guard_id}/policies", token=ta, org=oa)
    check("machine-only policy route refuses human session", st == 401, st)
    st, _ = call("POST", f"/api/v1/guards/{guard_id}/revoke", {}, token=tb, org=ob)
    check("BOLA: beta cannot revoke alpha's guard", st in (403, 404), st)
    st, own = call("GET", "/api/v1/guards", token=ta, org=oa)
    rows = own if isinstance(own, list) else (own or {}).get("guards", [])
    mine = [x for x in rows if x.get("id") == guard_id]
    check("BOLA: alpha's guard still unrevoked", bool(mine) and not mine[0].get("revoked_at") and mine[0].get("status") != "revoked",
          mine[0].get("status") if mine else "missing")
st, gl = call("GET", "/api/v1/guards", token=tb, org=ob)
check("beta sees no alpha guards", st == 200 and all(x.get("id") != guard_id for x in (gl if isinstance(gl, list) else gl.get("guards", []) if isinstance(gl, dict) else [])), st)
st, _ = call("GET", "/api/v1/guards")
check("unauthenticated refused", st == 401, st)
st, _ = call("POST", "/api/v1/gateway-installations/heartbeat", {})
check("gateway heartbeat route fail-closed", st == 422, st)

# RT-04: JSON body without Content-Type (FastAPI >= 0.132 rejects it).
st, _ = call("POST", "/api/v1/auth/login", {"email": A, "password": PW}, content_type=None)
results["RT-04 login JSON without Content-Type"] = {"observed": st, "note": "422 on the upgraded stack; 200 on the old stack"}

# RT-03: TOTP replay. Uses beta's account; disables MFA again afterwards.
st, setup = call("POST", "/api/v1/auth/mfa/setup", {}, token=tb, org=ob)
if st == 200:
    secret = urllib.parse.parse_qs(urllib.parse.urlparse(setup["provisioning_uri"]).query)["secret"][0]
    while int(time.time()) % 30 > 20:  # avoid crossing a step boundary mid-test
        time.sleep(1)
    now = int(time.time()) // 30
    st_en, _ = call("POST", "/api/v1/auth/mfa/enable", {"code": totp(secret, now - 1)}, token=tb, org=ob)
    code = totp(secret, now)
    st1, _ = call("POST", "/api/v1/auth/login", {"email": B, "password": PW, "totp_code": code})
    st2, _ = call("POST", "/api/v1/auth/login", {"email": B, "password": PW, "totp_code": code})
    observe("RT-03 TOTP replay rejected", st_en == 200 and st1 == 200 and st2 == 401,
            EXPECT_RT03 == "fixed")
    results["RT-03 TOTP replay rejected"]["statuses"] = {"enable": st_en, "first": st1, "replay": st2}
    # +1 step is inside the drift window and newer than any consumed step.
    st_dis, _ = call("POST", "/api/v1/auth/mfa/disable", {"code": totp(secret, now + 1)}, token=tb, org=ob)
    check("RT-03 cleanup: MFA disabled again", st_dis == 200, st_dis)
else:
    results["RT-03 TOTP replay rejected"] = {"pass": False, "detail": f"mfa setup {st}"}

print(json.dumps({"ok": all(v.get("pass") for v in results.values() if "pass" in v), "results": results}, indent=1))
