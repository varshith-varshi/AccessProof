"""The standalone client (stdlib only) against the REAL AccessProof Gateway +
Guard apps in remote mode: signatures interoperate, typed fail-closed errors,
provenance enforced client-side, LangChain and LlamaIndex adapters route every
answer through the Gateway. Run from the repository root:

  uv run --extra dev --with langchain-core --with llama-index-core \
      pytest integrations/rag-clients/python/tests
"""
from __future__ import annotations

import base64
import io
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from accessproof_rag import (AccessDenied, AccessProofGateway, IdentityRejected,  # noqa: E402
                             ProtectionUnavailable, TrustedChunk, UntrustedChunk)
from accessproof_rag import signing as client_signing  # noqa: E402
from packages.rag_core import request_signing as server_signing  # noqa: E402
from tests.security.test_gateway_all_response_routes import APP, _gateway  # noqa: E402
from tests.security.test_multisource_guard_v2 import _token  # noqa: E402

SECRET = b"k" * 40
B64 = base64.urlsafe_b64encode(SECRET).decode().rstrip("=")


@pytest.fixture()
def remote(tmp_path, monkeypatch):
    monkeypatch.setenv("ACCESSPROOF_GATEWAY_EXPOSURE", "remote")
    monkeypatch.setenv("ACCESSPROOF_GATEWAY_CLIENT_KEYS_JSON", json.dumps({"rag-win-01": B64}))
    monkeypatch.setenv("ACCESSPROOF_GATEWAY_TLS_TERMINATION", "proxy")
    gateway, _p, observed, chunk, *_ = _gateway(tmp_path, monkeypatch)
    with gateway:
        # Route the client's urllib calls into the in-process Gateway app.
        def fake_urlopen(req, timeout=None, context=None):
            r = gateway.request(req.get_method(), urllib.request.urlparse(req.full_url).path,
                                content=req.data, headers=dict(req.header_items()))
            if r.status_code >= 400:
                raise urllib.error.HTTPError(req.full_url, r.status_code, "x", {}, io.BytesIO(r.content))
            resp = io.BytesIO(r.content)
            resp.__enter__ = lambda *a: resp  # type: ignore[attr-defined]
            return _Resp(r.content)
        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        yield observed, chunk


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _client(secret=B64):
    return AccessProofGateway("https://gateway.example.internal:8443", application_id=APP,
                              client_id="rag-win-01", client_secret=secret)


def _tc(chunk):
    return TrustedChunk.from_metadata(chunk.content, {k: getattr(chunk, k) for k in
                                      ("source_id", "resource_id", "chunk_id", "content_version", "content_attestation")})


def test_signature_vectors_match_server_implementation():
    args = (SECRET, "POST", "/v1/chat/completions", 1700000000, "n" * 24, b'{"a":1}', "Bearer t")
    assert client_signing.sign(*args) == server_signing.sign(*args)
    assert client_signing.canonical(*args[1:]) == server_signing.canonical(*args[1:])


def test_authorized_employee_answer_goes_through_gateway(remote):
    observed, chunk = remote
    ans = _client().answer(_token("alice"), "What is available?", [_tc(chunk)], request_id="req-1")
    assert ans.text and ans.decision_id and ans.request_id == "req-1"
    assert observed["llm_count"] == 1


def test_unauthorized_employee_raises_and_model_not_called(remote):
    observed, chunk = remote
    with pytest.raises((AccessDenied, ProtectionUnavailable)):
        _client().answer(_token("bob"), "What is available?", [_tc(chunk)])
    assert observed["llm_count"] == 0


def test_wrong_application_secret_is_rejected(remote):
    observed, chunk = remote
    with pytest.raises(IdentityRejected) as e:
        _client(base64.urlsafe_b64encode(b"z" * 40).decode()).answer(_token("alice"), "q", [_tc(chunk)])
    assert e.value.code == "CLIENT_AUTHENTICATION_FAILED" and observed["llm_count"] == 0


def test_tampered_chunk_content_is_rejected_by_gateway(remote):
    observed, chunk = remote
    tc = _tc(chunk)
    forged = TrustedChunk(**{**tc.__dict__, "content": tc.content + " injected"})
    with pytest.raises((AccessDenied, ProtectionUnavailable, IdentityRejected)):
        _client().answer(_token("alice"), "q", [forged])
    assert observed["llm_count"] == 0


def test_chunk_without_provenance_never_leaves_the_client():
    with pytest.raises(UntrustedChunk):
        TrustedChunk.from_metadata("text", {"source_id": "s", "resource_id": "r"})


def test_plain_http_to_remote_host_refused():
    with pytest.raises(ValueError):
        AccessProofGateway("http://10.0.0.5:8080", application_id=APP)


def test_gateway_unreachable_raises_no_fallback(monkeypatch, remote):
    _observed, chunk = remote
    def boom(*a, **k):
        raise urllib.error.URLError("refused")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with pytest.raises(ProtectionUnavailable):
        _client().answer(_token("alice"), "q", [_tc(chunk)])


def _documents(chunk):
    from langchain_core.documents import Document
    md = {k: getattr(chunk, k) for k in ("source_id", "resource_id", "chunk_id", "content_version", "content_attestation")}
    return [Document(page_content=chunk.content, metadata=md)]


def test_langchain_runnable_routes_through_gateway(remote):
    pytest.importorskip("langchain_core")
    from langchain_core.retrievers import BaseRetriever

    from accessproof_rag.langchain import AccessProofRAG
    observed, chunk = remote
    docs = _documents(chunk)

    class Fixed(BaseRetriever):
        def _get_relevant_documents(self, query, *, run_manager=None):
            return docs

    rag = AccessProofRAG(retriever=Fixed(), gateway=_client())
    assert rag.invoke({"question": "What is available?", "employee_token": _token("alice")})
    with pytest.raises((AccessDenied, ProtectionUnavailable)):
        rag.invoke({"question": "What is available?", "employee_token": _token("bob")})
    assert observed["llm_count"] == 1


def test_llamaindex_query_engine_routes_through_gateway(remote):
    pytest.importorskip("llama_index.core")
    from llama_index.core.base.base_retriever import BaseRetriever
    from llama_index.core.schema import NodeWithScore, TextNode

    from accessproof_rag.llamaindex import AccessProofQueryEngine
    observed, chunk = remote
    md = {k: getattr(chunk, k) for k in ("source_id", "resource_id", "chunk_id", "content_version", "content_attestation")}

    class Fixed(BaseRetriever):
        def _retrieve(self, query_bundle):
            return [NodeWithScore(node=TextNode(text=chunk.content, metadata=md), score=1.0)]

    ok = AccessProofQueryEngine(retriever=Fixed(), gateway=_client(), employee_token=_token("alice"))
    assert str(ok.query("What is available?"))
    bad = AccessProofQueryEngine(retriever=Fixed(), gateway=_client(), employee_token=_token("bob"))
    with pytest.raises((AccessDenied, ProtectionUnavailable)):
        bad.query("What is available?")
    assert observed["llm_count"] == 1


def test_vendored_manifest_verifier_is_identical_to_server_copy():
    root = Path(__file__).resolve().parents[4]
    server = (root / "packages/rag_core/evidence_manifest.py").read_text()
    vendored = (Path(__file__).resolve().parents[1] / "accessproof_rag/_manifest.py").read_text()
    assert vendored.split("\n", 1)[1] == server
