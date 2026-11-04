"""AccessProof Gateway client for an existing RAG application (any OS).

The RAG keeps its own retrieval (any framework, any vector database). Instead
of calling the LLM itself it hands the question, the employee's identity token
and the retrieved TRUSTED chunks to the AccessProof Gateway, which:
  1. verifies each chunk's ingestion signature (provenance),
  2. asks the Guard which chunks this employee may use (Layer 1) and sends ONLY
     those to the model,
  3. re-checks authorization before releasing the answer (Layer 2).

Fail closed: every non-success raises; there is no fallback to a direct model
call, no cached-answer shortcut and no partial output.
"""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from .signing import signed_headers

TRUSTED_KEYS = ("source_id", "resource_id", "chunk_id", "content_version", "content_attestation")
CHAT_PATH = "/v1/chat/completions"


class AccessProofError(RuntimeError):
    def __init__(self, code: str, status: int | None = None, request_id: str | None = None):
        super().__init__(code)
        self.code, self.status, self.request_id = code, status, request_id


class IdentityRejected(AccessProofError):
    """401: the employee token (or the application signature) was rejected."""


class AccessDenied(AccessProofError):
    """403: the employee may not use any of the retrieved documents, or Layer 2 revoked."""


class ProtectionUnavailable(AccessProofError):
    """503 / network failure: authorization could not be established. Do NOT fall back."""


class UntrustedChunk(AccessProofError):
    """A retrieved chunk lacks trusted-ingestion provenance and cannot be sent."""


@dataclass(frozen=True)
class TrustedChunk:
    source_id: str
    resource_id: str
    chunk_id: str
    content: str
    content_version: str
    content_attestation: str

    @classmethod
    def from_metadata(cls, content: str, metadata: Mapping[str, Any]) -> "TrustedChunk":
        """Build from vector-store metadata written by AccessProof trusted ingestion.

        The content must be EXACTLY the attested bytes (do not re-split or
        normalize text after ingestion); the Gateway verifies the signature."""
        missing = [k for k in TRUSTED_KEYS if not isinstance(metadata.get(k), str) or not metadata.get(k)]
        if missing or not isinstance(content, str) or not content:
            raise UntrustedChunk("CHUNK_PROVENANCE_MISSING:" + ",".join(missing or ["content"]))
        return cls(content=content, **{k: str(metadata[k]) for k in TRUSTED_KEYS})

    def as_resource(self) -> dict[str, str]:
        return {"source_id": self.source_id, "resource_id": self.resource_id, "chunk_id": self.chunk_id,
                "content": self.content, "content_version": self.content_version,
                "content_attestation": self.content_attestation}


@dataclass(frozen=True)
class ProtectedAnswer:
    text: str
    decision_id: str
    request_id: str


class AccessProofGateway:
    """Signed HTTPS client for a remote AccessProof Gateway.

    client_secret: bytes or base64url string issued for this application
    (>= 32 bytes). ca_file: private CA bundle for the Gateway's certificate.
    client_cert/client_key: optional mTLS identity.
    """

    def __init__(self, base_url: str, *, application_id: str, client_id: str | None = None,
                 client_secret: bytes | str | None = None, ca_file: str | None = None,
                 client_cert: str | None = None, client_key: str | None = None,
                 timeout: float = 60.0, allow_insecure_loopback: bool = False) -> None:
        parts = urlsplit(base_url)
        loopback = parts.hostname in {"127.0.0.1", "localhost", "::1"}
        if parts.scheme != "https" and not (allow_insecure_loopback and loopback and parts.scheme == "http"):
            raise ValueError("The Gateway must be reached over HTTPS (http only for an explicit loopback test).")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("Gateway URL must not contain credentials, query or fragment")
        if (client_id is None) != (client_secret is None):
            raise ValueError("client_id and client_secret go together")
        if isinstance(client_secret, str):
            client_secret = base64.urlsafe_b64decode(client_secret + "=" * (-len(client_secret) % 4))
        if client_secret is not None and len(client_secret) < 32:
            raise ValueError("client secret must be at least 32 bytes")
        self.base_url = base_url.rstrip("/")
        self.application_id, self.client_id, self._secret = application_id, client_id, client_secret
        self.timeout = timeout
        self._ssl = None
        if parts.scheme == "https":
            self._ssl = ssl.create_default_context(cafile=ca_file)
            self._ssl.minimum_version = ssl.TLSVersion.TLSv1_2
            if client_cert:
                self._ssl.load_cert_chain(client_cert, client_key)

    def answer(self, employee_token: str, question: str, chunks: Sequence[TrustedChunk],
               *, request_id: str | None = None, conversation: Sequence[str] = ()) -> ProtectedAnswer:
        if not employee_token or not isinstance(employee_token, str):
            raise IdentityRejected("EMPLOYEE_TOKEN_REQUIRED")
        if not chunks:
            raise AccessDenied("NO_RETRIEVED_RESOURCES")
        request_id = request_id or f"rag-{uuid.uuid4()}"
        body = json.dumps({
            "application_id": self.application_id, "employee_question": question,
            "employee_conversation": [{"role": "user", "content": c} for c in conversation],
            "retrieved_resources": [c.as_resource() for c in chunks],
            "request_id": request_id, "stream": False,
        }, separators=(",", ":")).encode("utf-8")
        authorization = "Bearer " + employee_token
        headers = {"Authorization": authorization, "Content-Type": "application/json"}
        if self.client_id is not None and self._secret is not None:
            headers.update(signed_headers(self.client_id, self._secret, "POST", CHAT_PATH, body, authorization))
        req = urllib.request.Request(self.base_url + CHAT_PATH, data=body, headers=headers, method="POST")
        try:
            # Never retried: the protected request is one-time (Layer 1 context,
            # replay protection); a caller may start a NEW request.
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl) as resp:
                data = json.loads(resp.read(2_000_001))
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read(64_000)).get("detail")
            except (ValueError, AttributeError):
                detail = None
            code = detail.get("code") if isinstance(detail, dict) else (detail or f"HTTP_{exc.code}")
            cls = {401: IdentityRejected, 403: AccessDenied}.get(exc.code, ProtectionUnavailable)
            raise cls(str(code), exc.code, request_id) from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ProtectionUnavailable(f"GATEWAY_UNREACHABLE:{type(exc).__name__}", None, request_id) from None
        meta = data.get("accessproof") if isinstance(data, dict) else None
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ProtectionUnavailable("GATEWAY_RESPONSE_INVALID", None, request_id) from None
        if not isinstance(meta, dict) or meta.get("decision") != "allow" or not meta.get("decision_id") or not isinstance(text, str):
            raise ProtectionUnavailable("GATEWAY_RESPONSE_NOT_AUTHORIZED", None, request_id)
        return ProtectedAnswer(text=text, decision_id=str(meta["decision_id"]), request_id=request_id)
