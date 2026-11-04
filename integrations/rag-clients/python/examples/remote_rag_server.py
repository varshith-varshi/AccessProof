#!/usr/bin/env python3
"""Reference REMOTE RAG application (runs on any OS: Windows, Linux, macOS).

    python remote_rag_server.py --framework langchain --index trusted-index.json \
        --gateway https://ap-gateway.corp.internal:8443 --ca ap-gateway-ca.pem \
        --client-id rag-win-01 --listen 127.0.0.1:8187
    (client secret from --client-secret-file (preferred, 0600) or env AP_CLIENT_SECRET;
     never on the command line)

The employee-facing route is POST /chat with the employee's own bearer token.
Retrieval is local (a keyword retriever over the trusted-ingestion export);
generation happens ONLY behind the AccessProof Gateway. This host holds no
model credentials. GET /.well-known/accessproof-route describes the route for
certification (the certifier still verifies behaviour; it does not trust this).

--unsafe-* flags exist ONLY to prove that route certification rejects unsafe
deployments (a raw retrieval route, a direct-model route). Never use them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from accessproof_rag import (AccessDenied, AccessProofError, AccessProofGateway,  # noqa: E402
                             IdentityRejected, TrustedChunk, __version__)

REQUEST_ID = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")
MAX_BODY = 64_000


class KeywordIndex:
    def __init__(self, path: str):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.source_id, self.application_id = data["source_id"], data["application_id"]
        self.rows = data["chunks"]

    def search(self, question: str, limit: int = 5) -> list[dict]:
        tokens = set(re.findall(r"[a-z0-9]{2,}", question.lower())[:20])
        scored = []
        for row in self.rows:
            words = set(re.findall(r"[a-z0-9]{2,}", row["text"].lower()))
            hit = len(tokens & words)
            if hit:
                scored.append((-hit, row["chunk_id"], row))
        return [r for *_k, r in sorted(scored, key=lambda t: (t[0], t[1]))[:limit]]

    def metadata(self, row: dict) -> dict:
        return {"source_id": self.source_id, "resource_id": row["doc_id"], "chunk_id": row["chunk_id"],
                "content_version": row["version"], "content_attestation": row["attestation"]}


class SubscribedIndex:
    """Retrieval over the CURRENT verified evidence manifest. Raises
    EvidenceUnavailable when evidence is missing/expired (route answers 503)."""

    def __init__(self, cfg: dict):
        self.source_id, self.application_id = cfg["source_id"], cfg["application_id"]
        self.subscriber = None

    def search(self, question: str, limit: int = 5) -> list[dict]:
        return [{"doc_id": c.resource_id, "chunk_id": c.chunk_id, "text": c.content, "version": c.content_version,
                 "attestation": c.content_attestation} for c in self.subscriber.search(question, limit)]

    def metadata(self, row: dict) -> dict:
        return {"source_id": self.source_id, "resource_id": row["doc_id"], "chunk_id": row["chunk_id"],
                "content_version": row["version"], "content_attestation": row["attestation"]}


def build_answerer(framework: str, index: KeywordIndex, gateway: AccessProofGateway):
    if framework == "plain":
        def answer(question, token, request_id):
            chunks = [TrustedChunk.from_metadata(r["text"], index.metadata(r)) for r in index.search(question)]
            a = gateway.answer(token, question, chunks, request_id=request_id)
            return a.text, a.decision_id
        return answer
    if framework == "langchain":
        from langchain_core.documents import Document
        from langchain_core.retrievers import BaseRetriever

        from accessproof_rag.langchain import AccessProofRAG

        class Retriever(BaseRetriever):
            def _get_relevant_documents(self, query, *, run_manager=None):
                return [Document(page_content=r["text"], metadata=index.metadata(r)) for r in index.search(query)]

        chain = AccessProofRAG(retriever=Retriever(), gateway=gateway, return_answer=True)

        def answer(question, token, request_id):
            a = chain.invoke({"question": question, "employee_token": token, "request_id": request_id})
            return a.text, a.decision_id
        return answer
    if framework == "llamaindex":
        from llama_index.core.base.base_retriever import BaseRetriever
        from llama_index.core.schema import NodeWithScore, TextNode

        from accessproof_rag.llamaindex import AccessProofQueryEngine

        class Retriever(BaseRetriever):
            def _retrieve(self, query_bundle):
                return [NodeWithScore(node=TextNode(text=r["text"], metadata=index.metadata(r)), score=1.0)
                        for r in index.search(query_bundle.query_str)]

        retriever = Retriever()

        def answer(question, token, request_id):
            engine = AccessProofQueryEngine(retriever=retriever, gateway=gateway, employee_token=token,
                                            request_id=request_id)
            r = engine.query(question)
            return str(r), r.metadata["decision_id"]
        return answer
    raise SystemExit("framework must be plain, langchain or llamaindex")


def code_digest() -> str:
    h = hashlib.sha256()
    for p in sorted([Path(__file__).resolve(), *(HERE.parent / "accessproof_rag").glob("*.py")]):
        h.update(p.name.encode() + b"\0" + p.read_bytes())
    return h.hexdigest()


def framework_version(framework: str) -> str | None:
    from importlib.metadata import PackageNotFoundError, version
    name = {"langchain": "langchain-core", "llamaindex": "llama-index-core"}.get(framework)
    try:
        return version(name) if name else None
    except PackageNotFoundError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--framework", choices=["plain", "langchain", "llamaindex"], required=True)
    ap.add_argument("--index", help="static trusted-ingestion export (or use --evidence-subscribe)")
    ap.add_argument("--gateway", required=True)
    ap.add_argument("--ca")
    ap.add_argument("--client-id", required=True)
    ap.add_argument("--listen", default="127.0.0.1:8187")
    ap.add_argument("--client-secret-file", help="file holding the base64url client secret (preferred over env)")
    ap.add_argument("--evidence-subscribe", action="store_true",
                    help="continuously fetch refreshed signed trusted-ingestion evidence from the Gateway")
    ap.add_argument("--evidence-config", help="JSON: tenant_id, source_id, manifest_keys, attestation_keys")
    ap.add_argument("--evidence-cache", help="persisted verified manifest (survives restarts)")
    ap.add_argument("--evidence-interval", type=float, default=300.0)
    ap.add_argument("--unsafe-search-route", action="store_true")
    ap.add_argument("--unsafe-direct-model-route", action="store_true")
    a = ap.parse_args()
    secret = (Path(a.client_secret_file).read_text(encoding="utf-8").strip() if a.client_secret_file
              else os.environ.get("AP_CLIENT_SECRET"))
    if not secret:
        raise SystemExit("client secret required: --client-secret-file or AP_CLIENT_SECRET")
    subscriber = None
    if a.evidence_subscribe:
        from accessproof_rag.evidence import EvidenceSubscriber
        cfg = json.loads(Path(a.evidence_config).read_text(encoding="utf-8"))
        index = SubscribedIndex(cfg)
        gateway = AccessProofGateway(a.gateway, application_id=cfg["application_id"], client_id=a.client_id,
                                     client_secret=secret, ca_file=a.ca)
        subscriber = EvidenceSubscriber(gateway, source_id=cfg["source_id"], tenant_id=cfg["tenant_id"],
                                        application_id=cfg["application_id"], manifest_keys=cfg["manifest_keys"],
                                        attestation_keys=cfg["attestation_keys"], cache_path=a.evidence_cache,
                                        interval_seconds=a.evidence_interval)
        index.subscriber = subscriber
        subscriber.refresh_once()
        subscriber.start()
    else:
        index = KeywordIndex(a.index)
        gateway = AccessProofGateway(a.gateway, application_id=index.application_id, client_id=a.client_id,
                                     client_secret=secret, ca_file=a.ca)
    os.environ.pop("AP_CLIENT_SECRET", None)
    answer = build_answerer(a.framework, index, gateway)
    ca_sha = hashlib.sha256(Path(a.ca).read_bytes()).hexdigest() if a.ca else None
    manifest = {"schema": "accessproof.remote-rag-route/v1", "application_id": index.application_id,
                "client_id": a.client_id, "gateway_url": a.gateway, "gateway_ca_sha256": ca_sha,
                "framework": a.framework, "framework_version": framework_version(a.framework),
                "client_package": f"accessproof-rag/{__version__}", "code_sha256": code_digest(),
                "platform": sys.platform, "python": sys.version.split()[0],
                # Runtime configuration (flags, never secrets): part of the certified binding.
                "runtime_config_sha256": hashlib.sha256(json.dumps(
                    {**{k: v for k, v in sorted(vars(a).items()) if k != "client_secret_file"},
                     # pinned manifest/attestation keys are part of the certified configuration
                     "evidence_config_sha256": hashlib.sha256(Path(a.evidence_config).read_bytes()).hexdigest()
                     if a.evidence_config else None}).encode()).hexdigest(),
                "routes": [{"method": "POST", "path": "/chat", "protected_by": "accessproof-gateway"}]}

    class Handler(BaseHTTPRequestHandler):
        server_version = "remote-rag"
        sys_version = ""

        def log_message(self, fmt, *args):  # no tokens/content in logs
            sys.stderr.write("%s %s\n" % (self.command, self.path.split("?")[0]))

        def _send(self, status: int, body: dict) -> None:
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path == "/health":
                return self._send(200, {"status": "ok"})
            if self.path == "/.well-known/accessproof-route":
                return self._send(200, manifest)
            if self.path == "/health/evidence":
                if subscriber is None:
                    return self._send(404, {"detail": "STATIC_INDEX"})
                h = subscriber.health()
                return self._send(200 if h["state"] in ("OK", "DEGRADED") else 503, h)
            return self._send(404, {"detail": "NOT_FOUND"})

        def _question(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > MAX_BODY:
                return None
            try:
                q = json.loads(self.rfile.read(n)).get("question")
            except (ValueError, AttributeError):
                return None
            return q if isinstance(q, str) and 0 < len(q) <= 4000 else None

        def do_POST(self):
            path = self.path.split("?")[0]
            q = self._question()
            if q is None:
                return self._send(400, {"detail": "QUESTION_REQUIRED"})
            if a.unsafe_search_route and path == "/search":
                return self._send(200, {"results": [r["text"] for r in index.search(q)]})
            if a.unsafe_direct_model_route and path == "/chat/direct":
                return self._send(200, {"answer": " ".join(r["text"] for r in index.search(q))})
            if path != "/chat":
                return self._send(404, {"detail": "NOT_FOUND"})
            auth = self.headers.get("Authorization") or ""
            if not auth.startswith("Bearer ") or len(auth) < 20:
                return self._send(401, {"detail": "EMPLOYEE_TOKEN_REQUIRED"})
            rid = self.headers.get("X-Request-Id") or f"rag-{uuid.uuid4()}"
            if not REQUEST_ID.fullmatch(rid):
                return self._send(400, {"detail": "INVALID_REQUEST_ID"})
            if subscriber is not None:
                try:
                    subscriber.current()
                except AccessProofError as e:          # evidence expired/missing: fail closed
                    return self._send(503, {"detail": e.code, "request_id": rid})
            try:
                text, decision_id = answer(q, auth[7:], rid)
            except IdentityRejected as e:
                return self._send(401, {"detail": e.code, "request_id": rid})
            except AccessDenied as e:
                return self._send(403, {"detail": e.code, "request_id": rid})
            except AccessProofError as e:          # fail closed: no fallback answer
                return self._send(503, {"detail": e.code, "request_id": rid})
            except Exception:                      # noqa: BLE001 - never leak, never fall back
                return self._send(503, {"detail": "RAG_INTERNAL_ERROR", "request_id": rid})
            return self._send(200, {"answer": text, "cache_hit": False,
                                    "accessproof": {"decision": "allow", "decision_id": decision_id, "request_id": rid}})

    host, port = a.listen.rsplit(":", 1)
    print(json.dumps({"listening": a.listen, "framework": a.framework, "code_sha256": manifest["code_sha256"]}), flush=True)
    ThreadingHTTPServer((host, int(port)), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
