"""Local-only browser onboarding for the customer-side Guard.

The setup page is deliberately served by the Guard itself and is expected to
be published only on a loopback host port.  It exchanges a short-lived
bootstrap token without ever returning the resulting machine credential to the
browser.
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx


class EnrollmentError(RuntimeError):
    """A safe, user-facing enrollment failure."""


def validate_control_plane_url(value: str) -> str:
    url = value.strip().rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme == "https" and parsed.hostname:
        return url
    if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "api"}:
        return url
    raise EnrollmentError("Use an HTTPS control-plane URL (HTTP is allowed only for local development).")


def enroll_guard(
    *,
    server: str,
    token: str,
    version: str,
    state_dir: Path,
    issuer: str | None = None,
    audience: str | None = None,
    subject_claim: str = "sub",
    tenant_id: str | None = None,
    client: httpx.Client | None = None,
) -> dict[str, str]:
    """Exchange a one-time token and atomically persist private machine state."""
    server = validate_control_plane_url(server)
    if not token.strip():
        raise EnrollmentError("Enter the one-time enrollment token from AccessProof.")
    # Validate BEFORE exchanging the one-time token. An incomplete or malformed
    # identity configuration must never consume the enrollment credential.
    if not issuer or not issuer.strip() or not audience or not audience.strip():
        raise EnrollmentError("OIDC issuer and token audience are required before enrollment.")
    identity_issuer = issuer.strip().rstrip("/")
    identity_url = urlparse(identity_issuer)
    if (identity_url.scheme != "https" or not identity_url.hostname
            or identity_url.username or identity_url.password or identity_url.query or identity_url.fragment):
        raise EnrollmentError("OIDC issuer must be a trusted HTTPS URL.")
    if any(ch.isspace() for ch in audience.strip()):
        raise EnrollmentError("Token audience must be a single non-empty identifier.")
    # Enforce known immutable OIDC identifiers before consuming the one-time
    # enrollment token. Claims such as email or preferred_username are mutable.
    if subject_claim.strip() not in {"sub", "oid"}:
        raise EnrollmentError("Stable subject claim must be sub or oid.")
    # Do not silently rebind a Guard to a different tenant or overwrite a
    # machine credential while an old policy cache still exists.
    destination = state_dir / "credentials.json"
    if destination.exists() or destination.is_symlink():
        raise EnrollmentError("This Guard is already enrolled. Revoke it and provision a fresh isolated state directory.")
    owns_client = client is None
    http = client or httpx.Client(timeout=15, follow_redirects=False, trust_env=False)
    try:
        response = http.post(
            f"{server}/api/v1/guards/exchange",
            json={"enrollment_token": token.strip(), "version": version},
        )
        if response.status_code in {401, 403}:
            raise EnrollmentError("The enrollment token is invalid, expired, or already used.")
        response.raise_for_status()
        payload = response.json()
    except EnrollmentError:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        raise EnrollmentError("AccessProof could not be reached. Check the URL and network connection.") from exc
    finally:
        if owns_client:
            http.close()
    guard_id = payload.get("guard_id")
    credential = payload.get("guard_credential")
    if not isinstance(guard_id, str) or not isinstance(credential, str):
        raise EnrollmentError("The control plane returned an invalid enrollment response.")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    settings: dict[str, str] = {
        "control_plane_url": server,
        "guard_id": guard_id,
        "credential": credential,
        "identity_mode": "oidc",
        "subject_claim": subject_claim.strip() or "sub",
    }
    if issuer and issuer.strip():
        settings["issuer"] = identity_issuer
    if audience and audience.strip():
        settings["audience"] = audience.strip()
    if tenant_id and tenant_id.strip():
        settings["tenant_id"] = tenant_id.strip()
    temporary = state_dir / f".credentials.json.{secrets.token_hex(12)}.tmp"
    try:
        with temporary.open("x", encoding="utf-8") as file:
            os.chmod(temporary, 0o600)
            file.write(json.dumps(settings))
            file.flush()
            os.fsync(file.fileno())
        try:
            # Atomic no-overwrite: parallel CLI/browser enrollments cannot
            # silently replace another Guard's existing tenant credentials.
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise EnrollmentError("Guard state was enrolled concurrently; do not reuse this enrollment token.") from exc
    finally:
        temporary.unlink(missing_ok=True)
    return settings


def setup_page() -> str:
    """Self-contained setup UI; no remote JavaScript or analytics."""
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AccessProof Guard setup</title><style>
:root{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#10242d;background:#eef3f5}*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:28px}.shell{width:min(760px,100%);background:#fff;border:1px solid #cfdae0;border-radius:16px;box-shadow:0 24px 60px #18323f1a;overflow:hidden}
header{padding:28px 32px;background:#0e2a35;color:#fff}header small{color:#8fd0ea;font-weight:800;letter-spacing:.12em}h1{margin:8px 0 5px;font-size:28px}header p{margin:0;color:#bfd0d7}
main{padding:30px 32px}.progress{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:25px}.progress span{padding:9px;border-radius:7px;background:#edf4f7;color:#56717d;font-size:12px}.progress .active{background:#e2f2fa;color:#0876ad;font-weight:750}
label{display:block;margin:16px 0 6px;font-size:13px;font-weight:700}input{width:100%;padding:12px 13px;border:1px solid #bdcbd2;border-radius:7px;font:inherit}input:focus{outline:3px solid #d9eff9;border-color:#1385ba}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.hint{margin:6px 0 0;color:#657d88;font-size:12px;line-height:1.5}.actions{display:flex;align-items:center;gap:15px;margin-top:24px}button{padding:12px 19px;border:0;border-radius:7px;background:#087bb3;color:#fff;font-weight:750;cursor:pointer}button:disabled{opacity:.55;cursor:wait}
#message{font-size:13px}.ok{color:#16744c}.error{color:#b63737}.status{margin-top:22px;padding:14px;border:1px solid #d5e0e5;border-radius:8px;background:#f8fafb;font-size:13px}
@media(max-width:620px){body{padding:0}.shell{min-height:100vh;border-radius:0}.grid,.progress{grid-template-columns:1fr}header,main{padding:24px}}
</style></head><body><section class="shell"><header><small>ACCESSPROOF GUARD</small><h1>Connect this enforcement node</h1><p>Enroll securely, verify identity settings, and start policy synchronization.</p></header><main>
<div class="progress"><span class="active">1 · Connect</span><span>2 · Synchronize policy</span><span>3 · Protect the RAG</span></div>
<form id="setup"><label for="server">AccessProof control plane</label><input id="server" value="https://api.accessproof.in" required>
<label for="token">One-time enrollment token</label><input id="token" type="password" autocomplete="off" required><p class="hint">Create a Guard in web-v2 and paste the token here. It is exchanged once and is never stored in the browser.</p>
<div class="grid"><div><label for="issuer">OIDC issuer</label><input id="issuer" type="url" placeholder="https://login.example.com/tenant/v2.0" required></div><div><label for="audience">RAG token audience</label><input id="audience" placeholder="api://enterprise-rag" required></div></div>
<div class="grid"><div><label for="subject">Stable subject claim</label><input id="subject" value="sub"></div><div><label for="tenant">Tenant ID (optional)</label><input id="tenant"></div></div>
<div class="actions"><button id="connect">Connect Guard</button><span id="message" aria-live="polite"></span></div></form>
<div class="status" id="status">Checking Guard status…</div></main></section>
<script>
const byId=id=>document.getElementById(id);async function refresh(){try{const r=await fetch('/setup/status',{cache:'no-store'}),d=await r.json();byId('status').textContent=d.enrolled?`Connected · ${d.control_plane} · Guard ${d.guard_id_short} · ${d.sync_error?'Waiting for sync':'Synchronization active'}`:'Not enrolled yet';if(d.enrolled){byId('token').value='';}}catch{byId('status').textContent='Guard status is unavailable.'}}
byId('setup').addEventListener('submit',async e=>{e.preventDefault();const b=byId('connect'),m=byId('message');b.disabled=true;m.className='';m.textContent='Connecting…';try{const r=await fetch('/setup/enroll',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({server:byId('server').value,token:byId('token').value,issuer:byId('issuer').value||null,audience:byId('audience').value||null,subject_claim:byId('subject').value,tenant_id:byId('tenant').value||null})});const d=await r.json();if(!r.ok)throw new Error(d.detail||'Enrollment failed');m.className='ok';m.textContent='Connected. Policy synchronization is starting.';await refresh()}catch(err){m.className='error';m.textContent=err.message}finally{b.disabled=false}});refresh();setInterval(refresh,5000);
</script></body></html>"""


def public_status(settings: dict[str, Any], sync_error: str | None) -> dict[str, Any]:
    guard_id = str(settings.get("guard_id") or "")
    return {
        "enrolled": bool(guard_id and settings.get("credential")),
        "control_plane": settings.get("control_plane_url"),
        "guard_id_short": f"{guard_id[:8]}…" if guard_id else None,
        "sync_error": sync_error,
    }
