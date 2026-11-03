#!/usr/bin/env python3
"""Real employee identity for live SharePoint validation (operator laptop only).

    serve  --actor alice --client-id <public-client-app-id> --socket DIR/alice.sock [--flow auth-code|device]
           Interactive browser sign-in performed BY THE EMPLOYEE (this tool never
           sees a password): OAuth 2.0 Authorization Code + PKCE (S256) with a
           one-shot loopback listener on 127.0.0.1, exact `state` and OIDC
           `nonce` checks. Device code remains available with --flow device for
           tenants that permit it (Security Defaults block it: AADSTS530035). Verifies the ID token with the Guard's exact OIDC verifier
           (issuer, audience, tenant, immutable `oid`), cross-checks Graph /me,
           then keeps tokens IN MEMORY ONLY and serves them to local test tools
           over a 0600 Unix socket, refreshing (and re-verifying) before expiry.
    get    --socket DIR/alice.sock {id_token|access_token|claims}
    probe  --socket DIR/alice.sock --actor alice --out evidence.json
           Matrix test A: fetch each synthetic file's content AS THE EMPLOYEE
           (delegated Graph) and record SharePoint's own allow/deny.

Nothing here writes a token to disk or prints one (except `get`, which writes
to stdout for a pipe and refuses to write to a terminal).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import socket
import socketserver
import stat
import struct
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from apps.guard.accessproof_guard.identity import OidcVerifier  # noqa: E402

TENANT = "6479e7ca-b256-4ebc-a408-871b9046547c"
LOGIN = "https://login.microsoftonline.com/"
ISSUER = f"{LOGIN}{TENANT}/v2.0"
SCOPES = "openid profile offline_access User.Read Files.Read.All"
# The protected RAG/Gateway API. Its access token (aud = sign-in app, scp = access_as_user)
# is what the Guard accepts -- never the ID token.
API_SCOPE_NAME = "access_as_user"
UPN_DOMAIN = "neuralmatrix093.onmicrosoft.com"
SITE = "https://graph.microsoft.com/v1.0/sites/neuralmatrix093.sharepoint.com:/sites/AccessProof-Validation-20261027"
FOLDER = "Synthetic-RAG-Test"
EXPECTED = {
    "alice": {"finance_alice.txt": "ALLOW", "engineering_bob.txt": "DENY", "shared_control.txt": "ALLOW"},
    "bob": {"finance_alice.txt": "DENY", "engineering_bob.txt": "ALLOW", "shared_control.txt": "ALLOW"},
}
APP_ONLY_CONFIG = Path.home() / ".config/accessproof/entra-client-secret.json"


class IdentityFailure(RuntimeError):
    pass


def _claims(jwt_token: str) -> dict:
    part = jwt_token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _summary(claims: dict) -> dict:
    keep = ("iss", "tid", "oid", "aud", "ver", "iat", "exp", "preferred_username")
    out = {k: claims.get(k) for k in keep}
    out["sub_sha256"] = hashlib.sha256(str(claims.get("sub", "")).encode()).hexdigest()
    return out


class Session:
    """Tokens for ONE employee, held in memory only."""

    def __init__(self, actor: str, client_id: str):
        self.actor, self.client_id = actor, client_id
        self.http = httpx.Client(timeout=30, trust_env=False, follow_redirects=False)
        self.lock = threading.Lock()
        self.tokens: dict = {}
        self.verified: dict = {}

    def auth_code_sign_in(self, timeout_s: int = 600) -> None:
        """Authorization Code + PKCE through the employee's own browser."""
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        received: dict[str, str] = {}

        class Callback(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                parts = urlsplit(self.path)
                if parts.path != "/" or received:
                    self.send_response(404)
                    self.end_headers()
                    return
                received.update({k: v[0] for k, v in parse_qs(parts.query).items()})
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(b"AccessProof lab sign-in received. You can close this window.\n")

            def log_message(self, *args):  # never log the authorization code
                return

        server = HTTPServer(("127.0.0.1", 0), Callback)
        server.timeout = 2
        redirect = f"http://127.0.0.1:{server.server_address[1]}"
        url = f"{LOGIN}{TENANT}/oauth2/v2.0/authorize?" + urlencode({
            "client_id": self.client_id, "response_type": "code", "redirect_uri": redirect,
            "response_mode": "query", "scope": SCOPES, "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256",
            "login_hint": f"{self.actor}@{UPN_DOMAIN}", "prompt": "select_account",
        })
        print(f"SIGN-IN REQUIRED FOR: {self.actor.upper()} ({self.actor}@{UPN_DOMAIN})", flush=True)
        print("  Open this URL in a PRIVATE/INCOGNITO browser window. If the browser is on another", flush=True)
        print("  device, its final 127.0.0.1 page fails to load: copy that page's full URL to the operator,", flush=True)
        print("  who relays it to this listener (the code is useless without this process's PKCE verifier).", flush=True)
        print(f"  {url}", flush=True)
        end = time.monotonic() + timeout_s
        try:
            while not received and time.monotonic() < end:
                server.handle_request()
        finally:
            server.server_close()
        if not received:
            raise IdentityFailure("SIGN_IN_TIMED_OUT")
        if received.get("error"):
            raise IdentityFailure(f"SIGN_IN_FAILED:{received.get('error')}:{received.get('error_description', '')[:120]}")
        if not secrets.compare_digest(received.get("state", ""), state):
            raise IdentityFailure("STATE_MISMATCH")
        if not received.get("code"):
            raise IdentityFailure("AUTHORIZATION_CODE_MISSING")
        t = self.http.post(f"{LOGIN}{TENANT}/oauth2/v2.0/token", data={
            "grant_type": "authorization_code", "client_id": self.client_id, "code": received["code"],
            "redirect_uri": redirect, "code_verifier": verifier, "scope": SCOPES})
        if t.status_code != 200:
            raise IdentityFailure(f"CODE_REDEMPTION_FAILED:{t.json().get('error')}")
        self._accept(t.json(), expected_nonce=nonce)

    def device_sign_in(self) -> None:
        r = self.http.post(f"{LOGIN}{TENANT}/oauth2/v2.0/devicecode",
                           data={"client_id": self.client_id, "scope": SCOPES})
        if r.status_code != 200:
            raise IdentityFailure(f"DEVICE_CODE_UNAVAILABLE:{r.json().get('error')}")
        code = r.json()
        print(f"SIGN-IN REQUIRED FOR: {self.actor.upper()} ({self.actor}@{UPN_DOMAIN})", flush=True)
        print(f"  open: {code['verification_uri']}", flush=True)
        print(f"  code: {code['user_code']}   (expires in {code['expires_in']}s)", flush=True)
        pause, end = max(5, int(code.get("interval", 5))), time.monotonic() + int(code["expires_in"])
        while time.monotonic() < end:
            time.sleep(pause)
            t = self.http.post(f"{LOGIN}{TENANT}/oauth2/v2.0/token", data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": self.client_id, "device_code": code["device_code"]})
            if t.status_code == 200:
                self._accept(t.json())
                return
            err = t.json().get("error")
            if err == "authorization_pending":
                continue
            if err == "slow_down":
                pause += 5
                continue
            raise IdentityFailure(f"SIGN_IN_FAILED:{err}")
        raise IdentityFailure("SIGN_IN_EXPIRED")

    def _accept(self, grant: dict, expected_nonce: str | None = None) -> None:
        if not grant.get("id_token") or not grant.get("access_token"):
            raise IdentityFailure("TOKENS_MISSING")
        verifier = OidcVerifier(issuer=ISSUER, audience=self.client_id, subject_claim="oid", tenant_id=TENANT)
        try:
            ident = verifier.verify(grant["id_token"])  # signature, iss, aud, exp, tid, oid
        finally:
            verifier.close()
        if expected_nonce is not None and not secrets.compare_digest(str(ident.claims.get("nonce", "")), expected_nonce):
            raise IdentityFailure("NONCE_MISMATCH")
        me = self.http.get("https://graph.microsoft.com/v1.0/me",
                           headers={"Authorization": "Bearer " + grant["access_token"]},
                           params={"$select": "id,userPrincipalName,accountEnabled"})
        if me.status_code != 200:
            raise IdentityFailure("GRAPH_ME_FAILED")
        who = me.json()
        if who.get("id") != ident.subject or who.get("accountEnabled") is False:
            raise IdentityFailure("SIGNED_OID_DOES_NOT_MATCH_GRAPH_USER")
        if str(who.get("userPrincipalName", "")).lower() != f"{self.actor}@{UPN_DOMAIN}":
            raise IdentityFailure("WRONG_EMPLOYEE_SIGNED_IN")
        refresh_token = grant.get("refresh_token") or self.tokens.get("refresh_token")
        api_token = self._api_access_token(refresh_token)
        with self.lock:
            self.tokens = {"id_token": grant["id_token"], "access_token": grant["access_token"],
                           "api_token": api_token,
                           "refresh_token": refresh_token,
                           "id_exp": min(int(_claims(grant["id_token"])["exp"]), int(_claims(api_token)["exp"]))}
            self.verified = {"actor": self.actor, "verified_at": datetime.now(timezone.utc).isoformat(),
                             "guard_verifier": "apps.guard.accessproof_guard.identity.OidcVerifier",
                             "subject_claim": "oid", "graph_me_oid_match": True,
                             "upn": who["userPrincipalName"].lower(),
                             "id_token_claims": _summary(_claims(grant["id_token"]))}
        print(f"VERIFIED {self.actor}: oid={ident.subject} tid={ident.tenant_id} iss={ident.issuer}", flush=True)

    def _api_access_token(self, refresh_token: str | None) -> str:
        """Delegated access token for the protected RAG API, verified exactly as
        the Guard will verify it (audience, tenant, signature, scope, oid)."""
        if not refresh_token:
            raise IdentityFailure("NO_REFRESH_TOKEN_FOR_API_TOKEN")
        r = self.http.post(f"{LOGIN}{TENANT}/oauth2/v2.0/token", data={
            "grant_type": "refresh_token", "client_id": self.client_id, "refresh_token": refresh_token,
            "scope": f"api://{self.client_id}/{API_SCOPE_NAME} offline_access"})
        if r.status_code != 200:
            raise IdentityFailure(f"API_TOKEN_FAILED:{r.json().get('error')}")
        token = r.json()["access_token"]
        verifier = OidcVerifier(issuer=ISSUER, audience=self.client_id, subject_claim="oid",
                                tenant_id=TENANT, required_scope=API_SCOPE_NAME)
        try:
            verifier.verify(token)
        finally:
            verifier.close()
        return token

    def refresh_if_needed(self) -> None:
        with self.lock:
            due = self.tokens and self.tokens["id_exp"] - time.time() < 600
            rt = self.tokens.get("refresh_token")
        if not due:
            return
        if not rt:
            raise IdentityFailure("NO_REFRESH_TOKEN")
        r = self.http.post(f"{LOGIN}{TENANT}/oauth2/v2.0/token", data={
            "grant_type": "refresh_token", "client_id": self.client_id,
            "refresh_token": rt, "scope": SCOPES})
        if r.status_code != 200:
            raise IdentityFailure(f"REFRESH_FAILED:{r.json().get('error')}")
        self._accept(r.json())

    def get(self, what: str) -> str:
        with self.lock:
            if what == "claims":
                return json.dumps(self.verified)
            if what in ("id_token", "access_token", "api_token") and self.tokens:
                return self.tokens[what]
        raise IdentityFailure("UNKNOWN_OR_NOT_READY")


def serve(args) -> int:
    sock_path = Path(args.socket)
    sock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if stat.S_IMODE(sock_path.parent.stat().st_mode) != 0o700:
        raise IdentityFailure("SOCKET_DIRECTORY_MUST_BE_0700")
    session = Session(args.actor, args.client_id)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            # Only processes of the same OS user may obtain tokens.
            _pid, uid, _gid = struct.unpack("3i", self.request.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if uid != os.getuid():
                return
            what = self.rfile.readline(64).decode().strip()
            try:
                self.wfile.write((session.get(what) + "\n").encode())
            except IdentityFailure as exc:
                self.wfile.write(f"ERROR {exc}\n".encode())

    sock_path.unlink(missing_ok=True)
    old = os.umask(0o177)
    try:
        server = socketserver.UnixStreamServer(str(sock_path), Handler)
    finally:
        os.umask(old)  # never leak the restrictive umask, even on failure
    # The socket is bound BEFORE anyone is asked to sign in, so a local
    # failure can never waste a completed employee sign-in.
    session.auth_code_sign_in(timeout_s=args.signin_timeout) if args.flow == "auth-code" else session.device_sign_in()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"SERVING {args.actor} tokens on {sock_path} (in memory only) for up to {args.max_hours}h", flush=True)
    end = time.monotonic() + args.max_hours * 3600
    try:
        while time.monotonic() < end:
            session.refresh_if_needed()
            time.sleep(30)
    finally:
        server.shutdown()
        sock_path.unlink(missing_ok=True)
    return 0


def fetch(sock: str, what: str) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(sock)
        s.sendall((what + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    value = data.decode().strip()
    if value.startswith("ERROR"):
        raise IdentityFailure(value)
    return value


def _app_only_token(http: httpx.Client) -> str:
    cfg = json.loads(APP_ONLY_CONFIG.read_text())
    r = http.post(f"{LOGIN}{TENANT}/oauth2/v2.0/token", data={
        "grant_type": "client_credentials", "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"], "scope": "https://graph.microsoft.com/.default"})
    if r.status_code != 200:
        raise IdentityFailure("APP_ONLY_TOKEN_FAILED")
    return r.json()["access_token"]


def item_refs(http: httpx.Client) -> tuple[str, dict[str, str]]:
    """Locate the fixed synthetic items with the AccessProof app identity only."""
    h = {"Authorization": "Bearer " + _app_only_token(http)}
    site = http.get(SITE, headers=h)
    site.raise_for_status()
    drives = http.get(f"https://graph.microsoft.com/v1.0/sites/{quote(site.json()['id'], safe='')}/drives", headers=h)
    drives.raise_for_status()
    docs = [d for d in drives.json()["value"] if d.get("name") == "Documents"]
    if len(docs) != 1:
        raise IdentityFailure("DOCUMENTS_LIBRARY_AMBIGUOUS")
    drive = docs[0]["id"]
    kids = http.get(f"https://graph.microsoft.com/v1.0/drives/{quote(drive, safe='')}/root:/{FOLDER}:/children", headers=h)
    kids.raise_for_status()
    items = {i["name"]: i["id"] for i in kids.json()["value"] if i.get("file")}
    return drive, items


def delegated_decision(http: httpx.Client, drive: str, item: str, user_token: str) -> tuple[str, int]:
    url = f"https://graph.microsoft.com/v1.0/drives/{quote(drive, safe='')}/items/{quote(item, safe='')}/content"
    r = http.get(url, headers={"Authorization": "Bearer " + user_token})
    if r.status_code in (200, 206):
        return "ALLOW", r.status_code
    if r.status_code == 302:
        host = urlsplit(r.headers.get("location", "")).hostname or ""
        if host.endswith((".sharepoint.com", ".sharepointonline.com", ".1drv.com")):
            return "ALLOW", 302
    if r.status_code in (403, 404):
        return "DENY", r.status_code
    return "AMBIGUOUS", r.status_code


def probe(args) -> int:
    claims = json.loads(fetch(args.socket, "claims"))
    token = fetch(args.socket, "access_token")
    rows = []
    with httpx.Client(timeout=30, trust_env=False, follow_redirects=False) as http:
        drive, items = item_refs(http)
        for name, expected in EXPECTED[args.actor].items():
            if name not in items:
                rows.append({"document": name, "expected": expected, "actual": "MISSING", "status": None, "pass": False})
                continue
            decision, status = delegated_decision(http, drive, items[name], token)
            rows.append({"document": name, "item_id": items[name], "expected": expected,
                         "actual": decision, "http_status": status, "pass": decision == expected,
                         "at": datetime.now(timezone.utc).isoformat()})
    # D-21: a 403/404 only means "SharePoint denies" if the SAME token can read
    # the documents this employee IS entitled to. Without that positive control
    # (e.g. a token lacking delegated Files.Read.All) every cell would look like
    # DENY and deny expectations would falsely pass.
    positive_control = any(r["expected"] == "ALLOW" and r.get("actual") == "ALLOW" for r in rows)
    if not positive_control:
        for r in rows:
            if r.get("actual") == "DENY":
                r["actual"], r["pass"] = "INCONCLUSIVE_NO_POSITIVE_CONTROL", False
    out = {"schema": "accessproof.direct_sharepoint_probe/v1", "actor": args.actor,
           "identity": claims, "drive_id": drive, "results": rows,
           "positive_control": positive_control,
           "pass": positive_control and all(r["pass"] for r in rows)}
    Path(args.out).write_text(json.dumps(out, indent=1))
    print(json.dumps({"actor": args.actor, "pass": out["pass"],
                      "results": [(r["document"], r["expected"], r["actual"], r.get("http_status")) for r in rows]}))
    return 0 if out["pass"] else 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--actor", choices=sorted(EXPECTED), required=True)
    s.add_argument("--client-id", required=True)
    s.add_argument("--socket", required=True)
    s.add_argument("--max-hours", type=float, default=8.0)
    s.add_argument("--flow", choices=["auth-code", "device"], default="auth-code")
    s.add_argument("--signin-timeout", type=int, default=1800,
                   help="seconds to wait for the browser callback (a remote browser's failed "
                        "127.0.0.1 redirect URL can be relayed to the listener by the operator)")
    g = sub.add_parser("get")
    g.add_argument("--socket", required=True)
    g.add_argument("what", choices=["id_token", "access_token", "api_token", "claims"])
    pr = sub.add_parser("probe")
    pr.add_argument("--socket", required=True)
    pr.add_argument("--actor", choices=sorted(EXPECTED), required=True)
    pr.add_argument("--out", required=True)
    a = p.parse_args()
    try:
        if a.cmd == "serve":
            return serve(a)
        if a.cmd == "get":
            if a.what != "claims" and sys.stdout.isatty():
                print("refusing to print a token to a terminal; pipe it", file=sys.stderr)
                return 2
            sys.stdout.write(fetch(a.socket, a.what))
            return 0
        return probe(a)
    except IdentityFailure as exc:
        print(f"IDENTITY_FAILURE {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
