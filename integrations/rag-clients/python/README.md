# accessproof-rag — connect an existing RAG application to AccessProof

Pure-Python (stdlib only, Python ≥ 3.10), so it runs unchanged on **Windows, Linux and macOS**.
There's no Docker, WSL or Ubuntu requirement on the RAG server. The RAG keeps its own
retriever and vector database. Only the *generation* step moves behind the AccessProof Gateway:

```
employee ──token──▶ your RAG (any host/OS) ──retrieve──▶ your vector DB
                         │  signed HTTPS (ap-req-v1) + employee token + trusted chunks
                         ▼
             AccessProof Gateway (Linux) ──Layer 1/2──▶ Guard ──▶ model
```

## Install

```
pip install "accessproof-rag[langchain]"      # or [llamaindex], or no extra
# from source: pip install ./integrations/rag-clients/python
```

## What your AccessProof administrator gives you

| Item | Example | Where it lives on the RAG host |
|---|---|---|
| Gateway URL (HTTPS only) | `https://ap-gateway.corp.internal:8443` | config |
| Application id | `hr-assistant` | config |
| Client id + secret (≥ 32 bytes, base64url) | `rag-win-01` | secret store / env var, **never in code** |
| Gateway CA bundle (private PKI) | `ap-gateway-ca.pem` | file |

Chunks in your vector database must come from **AccessProof trusted ingestion**. They carry the
metadata `source_id, resource_id, chunk_id, content_version, content_attestation`, and the exact
attested text. A chunk without provenance raises `UntrustedChunk` and never leaves the client.

## Plain Python

```python
import os
from accessproof_rag import AccessProofGateway, TrustedChunk, AccessDenied, ProtectionUnavailable

gw = AccessProofGateway(os.environ["AP_GATEWAY_URL"], application_id="hr-assistant",
                        client_id="rag-win-01", client_secret=os.environ["AP_CLIENT_SECRET"],
                        ca_file=r"C:\accessproof\ap-gateway-ca.pem")
chunks = [TrustedChunk.from_metadata(hit.text, hit.metadata) for hit in my_search(question)]
try:
    answer = gw.answer(employee_access_token, question, chunks, request_id=req_id).text
except AccessDenied:          # 403: not authorized / revoked mid-request
    answer = "You don't have access to the documents needed to answer this."
except ProtectionUnavailable: # 503 / network: authorization unknown -> do NOT call a model yourself
    answer = "Protected answers are temporarily unavailable."
```

## LangChain

```python
from accessproof_rag.langchain import AccessProofRAG
rag = AccessProofRAG(retriever=vectorstore.as_retriever(), gateway=gw)
rag.invoke({"question": q, "employee_token": token, "request_id": req_id})
```

## LlamaIndex

```python
from accessproof_rag.llamaindex import AccessProofQueryEngine
engine = AccessProofQueryEngine(retriever=index.as_retriever(), gateway=gw, employee_token=token)
engine.query(q)
```

## Security properties (enforced, not optional)

* HTTPS only to non-loopback hosts. TLS ≥ 1.2 with a pinned CA bundle. mTLS is supported via `client_cert`/`client_key`.
* Every request is HMAC-signed over the method, path, timestamp, single-use nonce, body hash and **employee
  token hash**. A captured request can't be replayed, altered, or re-used with another employee's token.
* Every failure raises. There's no fallback to a direct model call, no cached-answer shortcut, and no retry of
  a protected request.
* **Remove direct model credentials from the RAG host.** Route certification probes for a direct-model
  path and refuses to certify while one exists.

## Tests

```
uv run --extra dev --with langchain-core --with llama-index-core pytest integrations/rag-clients/python/tests
```
