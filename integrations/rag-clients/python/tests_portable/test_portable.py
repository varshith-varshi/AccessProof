"""OS-portable tests (Windows / macOS / Linux): no AccessProof server code.

A local TLS mock Gateway independently re-derives and verifies the ap-req-v1
signature (its own canonical implementation, not the client's), so the client
and the reference remote RAG server are exercised as real processes on the
target OS. Run:  pip install cryptography pytest langchain-core llama-index-core
                 pytest integrations/rag-clients/python/tests_portable
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))
from accessproof_rag import AccessDenied, AccessProofGateway, ProtectionUnavailable, TrustedChunk, UntrustedChunk  # noqa: E402
from accessproof_rag.signing import sign  # noqa: E402

SECRET = b"p" * 32
SECRET_B64 = base64.urlsafe_b64encode(SECRET).decode().rstrip("=")
# Fixed vector computed by the Linux server implementation (packages/rag_core/request_signing.py).
VECTOR = ((SECRET, "POST", "/v1/chat/completions", 1700000000, "n" * 24, b'{"a":1}', "Bearer t"), None)
META = {"source_id": "s", "resource_id": "r", "chunk_id": "c", "content_version": "v1", "content_attestation": "att"}


def _independent_sig(secret, method, path, ts, nonce, body, auth):
    canon = "\n".join(["ap-req-v1", method, path, str(ts), nonce, hashlib.sha256(body).hexdigest(),
                       hashlib.sha256(auth.encode()).hexdigest()]).encode()
    return base64.urlsafe_b64encode(hmac.new(secret, canon, hashlib.sha256).digest()).rstrip(b"=").decode()


def test_signature_matches_independent_derivation():
    assert sign(*VECTOR[0]) == _independent_sig(*VECTOR[0])


@pytest.fixture(scope="module")
def tls_gateway(tmp_path_factory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    d = tmp_path_factory.mktemp("pki")
    now = dt.datetime.now(dt.timezone.utc)
    ca_key, srv_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "portable test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    srv = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
           .issuer_name(ca_name).public_key(srv_key.public_key()).serial_number(2).not_valid_before(now)
           .not_valid_after(now + dt.timedelta(days=1))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
           .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
           .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
           .sign(ca_key, hashes.SHA256()))
    (d / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (d / "srv.pem").write_bytes(srv.public_bytes(serialization.Encoding.PEM))
    (d / "srv.key").write_bytes(srv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()))
    seen = {"calls": [], "nonces": set()}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            h = self.headers
            expected = _independent_sig(SECRET, "POST", self.path, int(h["X-AccessProof-Timestamp"]), h["X-AccessProof-Nonce"],
                                        body, h["Authorization"])
            if not hmac.compare_digest(expected, h.get("X-AccessProof-Signature", "")) or h["X-AccessProof-Nonce"] in seen["nonces"]:
                return self._send(401, {"detail": "CLIENT_AUTHENTICATION_FAILED"})
            seen["nonces"].add(h["X-AccessProof-Nonce"])
            req = json.loads(body)
            seen["calls"].append(req)
            token = h["Authorization"][7:]
            if token == "bob-token":
                return self._send(403, {"detail": {"code": "NO_AUTHORIZED_RESOURCES"}})
            if token == "outage":
                return self._send(503, {"detail": {"code": "GUARD_UNAVAILABLE"}})
            self._send(200, {"choices": [{"message": {"content": "answer from " + req["retrieved_resources"][0]["resource_id"]}}],
                             "accessproof": {"decision": "allow", "decision_id": "d-1", "request_id": req["request_id"]}})

        def _send(self, status, obj):
            raw = json.dumps(obj).encode()
            self.send_response(status); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    srv_http = ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(d / "srv.pem", d / "srv.key")
    srv_http.socket = ctx.wrap_socket(srv_http.socket, server_side=True)
    threading.Thread(target=srv_http.serve_forever, daemon=True).start()
    yield {"url": f"https://localhost:{srv_http.server_address[1]}", "ca": str(d / "ca.pem"), "seen": seen, "dir": d}
    srv_http.shutdown()


def _gw(g):
    return AccessProofGateway(g["url"], application_id="app", client_id="rag-win-01", client_secret=SECRET_B64, ca_file=g["ca"])


def test_signed_tls_round_trip_and_typed_denials(tls_gateway):
    chunk = TrustedChunk.from_metadata("text", META)
    assert _gw(tls_gateway).answer("alice-token", "q", [chunk]).text == "answer from r"
    with pytest.raises(AccessDenied):
        _gw(tls_gateway).answer("bob-token", "q", [chunk])
    with pytest.raises(ProtectionUnavailable):
        _gw(tls_gateway).answer("outage", "q", [chunk])


def test_untrusted_ca_is_refused(tls_gateway):
    gw = AccessProofGateway(tls_gateway["url"], application_id="app", client_id="rag-win-01", client_secret=SECRET_B64)
    with pytest.raises(ProtectionUnavailable):
        gw.answer("alice-token", "q", [TrustedChunk.from_metadata("text", META)])


def test_provenance_and_https_enforced():
    with pytest.raises(UntrustedChunk):
        TrustedChunk.from_metadata("text", {"source_id": "s"})
    with pytest.raises(ValueError):
        AccessProofGateway("http://10.1.2.3:8080", application_id="app")


@pytest.mark.parametrize("framework", ["plain", "langchain", "llamaindex"])
def test_reference_remote_rag_server_runs_on_this_os(tls_gateway, framework):
    if framework != "plain":
        pytest.importorskip({"langchain": "langchain_core", "llamaindex": "llama_index.core"}[framework])
    d = tls_gateway["dir"]
    (d / "index.json").write_text(json.dumps({"source_id": "s", "application_id": "app", "chunks": [
        {"doc_id": "r", "chunk_id": "c", "text": "finance budget synthetic", "version": "v1", "name": "f", "attestation": "att"}]}))
    (d / "secret").write_text(SECRET_B64)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
    proc = subprocess.Popen([sys.executable, str(PKG / "examples" / "remote_rag_server.py"), "--framework", framework,
                             "--index", str(d / "index.json"), "--gateway", tls_gateway["url"], "--ca", tls_gateway["ca"],
                             "--client-id", "rag-win-01", "--client-secret-file", str(d / "secret"),
                             "--listen", f"127.0.0.1:{port}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1); break
            except OSError:
                time.sleep(0.2)
        manifest = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/.well-known/accessproof-route").read())
        assert manifest["platform"] == sys.platform and manifest["framework"] == framework
        def ask(tok):
            req = urllib.request.Request(f"http://127.0.0.1:{port}/chat", data=json.dumps({"question": "finance budget"}).encode(),
                                         headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())
        assert ask("alice-token-long-enough")[0] == 200
        assert ask("bob-token")[0] in (401, 403)          # short token rejected locally or denied by Gateway
        assert ask("outage-token-long-enough-x")[0] in (200, 503)
        assert ask("")[0] == 401
    finally:
        proc.terminate(); proc.wait(10)
