"""Source-backed provenance checks at the actual SDK model-input/release boundary."""
from __future__ import annotations

from dataclasses import replace

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from packages.rag_sdk import (
    ContentBinding, ProtectedRAG, RetrievedResource,
    SourceAttestationSigner, SourceAttestationVerifier,
)


class SyntheticAllowingGuard:
    def __init__(self):
        self.filter_calls = 0
        self.output_calls = 0

    def filter_resources(self, *, resources, **kwargs):
        self.filter_calls += 1
        return {
            "mode": "protect", "decision": "allow", "decision_id": "safe-l1",
            "allowed": [
                {"source_id": doc.source_id, "resource_id": doc.resource_id, "chunk_ids": []}
                for doc in resources
            ],
        }

    def check_output(self, **kwargs):
        self.output_calls += 1
        return {"decision": "allow", "reason": "SYNTHETIC_VALID"}


@pytest.fixture
def provenance():
    key = Ed25519PrivateKey.generate()
    signer = SourceAttestationSigner(key_id="source-ingest-v1", private_key=key)
    verifier = SourceAttestationVerifier(
        tenant_id="tenant-a", trusted_keys={"source-ingest-v1": key.public_key()},
    )
    resource = RetrievedResource(
        source_id="drive", resource_id="public-file",
        chunk_id="chunk-1", content="PUBLIC VERIFIED TEXT",
        content_version="revision-44",
    )

    def attest(resource, *, signer=signer, tenant="tenant-a", application="rag-app", now=None):
        binding = ContentBinding(
            tenant_id=tenant, application_id=application,
            source_id=resource.source_id, resource_id=resource.resource_id,
            chunk_id=resource.chunk_id, content_version=resource.content_version,
            content=resource.content,
        )
        return replace(resource, content_attestation=signer.issue(binding, now=now))

    return signer, verifier, attest(resource), attest


def test_trusted_source_content_reaches_generator_and_buffered_layer2(provenance):
    _, verifier, valid, _ = provenance
    guard = SyntheticAllowingGuard()
    inspected = []
    result = ProtectedRAG(guard, provenance_verifier=verifier).run(
        employee_token="synthetic", application_id="rag-app",
        retrieved=[valid], generate=lambda docs: inspected.extend(docs) or docs[0].content,
        source_trace=lambda: [valid],
    )
    assert result.response == valid.content
    assert result.decision == "allow"
    assert result.provenance_level == "SOURCE_ATTESTED"
    assert result.certification_eligible is True
    assert inspected == [valid]
    assert guard.output_calls == 1


@pytest.mark.parametrize("attack", [
    "missing_attestation", "altered_bytes", "foreign_source", "wrong_resource",
    "wrong_tenant", "wrong_application", "wrong_revision", "expired", "untrusted_signer",
])
def test_adversarial_source_byte_substitution_blocks_before_model(attack, provenance):
    signer, verifier, valid, attest = provenance
    forged = {
        "missing_attestation": replace(valid, content_attestation=None),
        "altered_bytes": replace(valid, content="SYNTHETIC PRIVATE PAYROLL SECRET"),
        "foreign_source": replace(valid, source_id="drive-private"),
        "wrong_resource": replace(valid, resource_id="restricted-payroll"),
        "wrong_tenant": attest(replace(valid, content_attestation=None), tenant="tenant-b"),
        "wrong_application": attest(replace(valid, content_attestation=None), application="other-rag"),
        "wrong_revision": replace(valid, content_version="revision-45"),
        "expired": attest(replace(valid, content_attestation=None), now=1),
        "untrusted_signer": attest(
            replace(valid, content_attestation=None),
            signer=SourceAttestationSigner(
                key_id="source-ingest-v1", private_key=Ed25519PrivateKey.generate(),
            ),
        ),
    }[attack]
    guard = SyntheticAllowingGuard()
    calls = []
    outcome = ProtectedRAG(guard, provenance_verifier=verifier).run(
        employee_token="synthetic", application_id="rag-app", retrieved=[forged],
        generate=lambda docs: calls.append(docs) or "LEAKED",
        source_trace=lambda: [forged],
    )
    assert outcome.decision == "block"
    assert outcome.response is None
    assert outcome.reason == "SOURCE_CONTENT_ATTESTATION_FAILED"
    assert calls == []
    assert guard.output_calls == 0


def test_untrusted_late_tool_provenance_blocks_final_response(provenance):
    _, verifier, valid, _ = provenance
    guard = SyntheticAllowingGuard()
    injected = replace(valid, content="INJECTED_TOOL_SECRET")
    result = ProtectedRAG(guard, provenance_verifier=verifier).run(
        employee_token="synthetic", application_id="rag-app",
        retrieved=[valid],
        generate=lambda docs: "PUBLIC RESPONSE",
        source_trace=lambda: [valid, injected],
    )
    assert result.response is None
    assert result.reason == "SOURCE_TRACE_ATTESTATION_FAILED"
    assert guard.output_calls == 0


def test_declared_provenance_without_trusted_source_bytes_is_rejected(provenance):
    _, verifier, valid, _ = provenance
    result = ProtectedRAG(SyntheticAllowingGuard(), provenance_verifier=verifier).run(
        employee_token="synthetic", application_id="rag-app",
        retrieved=[valid], generate=lambda docs: docs[0].content,
        source_trace=lambda: [RetrievedResource("drive", "public-file")],
    )
    assert result.decision == "block"
    assert result.response is None
    assert result.reason == "SOURCE_TRACE_ATTESTATION_FAILED"


def test_source_binding_token_cannot_be_treated_as_authorization_on_its_own(provenance):
    _, verifier, valid, _ = provenance

    class DenyingGuard(SyntheticAllowingGuard):
        def filter_resources(self, *, resources, **kwargs):
            return {"decision": "block", "mode": "protect", "decision_id": "d",
                    "allowed": []}

    output = ProtectedRAG(DenyingGuard(), provenance_verifier=verifier).run(
        employee_token="synthetic", application_id="rag-app",
        retrieved=[valid], generate=lambda docs: "PRIVATE",
        source_trace=lambda: [valid],
    )
    assert output.response is None
    assert output.decision == "block"


def test_regeneration_requires_complete_attested_input_trace(provenance):
    _, verifier, first, attest = provenance
    second = attest(replace(
        first, resource_id="other-document", content="OTHER_SOURCE_CONTENT",
        content_attestation=None,
    ))

    class RegenerationGuard(SyntheticAllowingGuard):
        def check_output(self, **kwargs):
            self.output_calls += 1
            if self.output_calls == 1:
                return {"decision": "block", "reason": "SYNTHETIC_REGENERATE"}
            return {"decision": "allow", "reason": "SYNTHETIC_REGENERATED"}

    guard = RegenerationGuard()
    traces = 0

    def trace():
        nonlocal traces
        traces += 1
        return [first, second] if traces == 1 else [first]

    result = ProtectedRAG(
        guard, provenance_verifier=verifier, max_regenerations=1,
    ).run(
        employee_token="synthetic", application_id="rag-app",
        retrieved=[first, second],
        generate=lambda docs: "PRELIMINARY",
        regenerate=lambda docs: docs[-1].content,
        source_trace=trace,
    )
    assert result.decision == "block"
    assert result.response is None
    assert guard.output_calls == 1


def test_tampered_attestation_signature_blocks_before_model(provenance):
    _, verifier, valid, _ = provenance
    payload, signature = valid.content_attestation.split(".")
    flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
    forged = replace(valid, content_attestation=f"{payload}.{flipped}")
    calls = []
    result = ProtectedRAG(SyntheticAllowingGuard(), provenance_verifier=verifier).run(
        employee_token="synthetic", application_id="rag-app", retrieved=[forged],
        generate=lambda docs: calls.append(docs) or "LEAKED",
        source_trace=lambda: [forged],
    )
    assert result.decision == "block"
    assert result.reason == "SOURCE_CONTENT_ATTESTATION_FAILED"
    assert calls == []


def test_revoked_ingestion_key_blocks_before_model(provenance):
    _, _, valid, _ = provenance
    replacement = Ed25519PrivateKey.generate()
    verifier = SourceAttestationVerifier(
        tenant_id="tenant-a",
        trusted_keys={"replacement-key": replacement.public_key()},
        revoked_key_ids={"source-ingest-v1"},
    )
    calls = []
    result = ProtectedRAG(SyntheticAllowingGuard(), provenance_verifier=verifier).run(
        employee_token="synthetic", application_id="rag-app", retrieved=[valid],
        generate=lambda docs: calls.append(docs) or "LEAKED",
        source_trace=lambda: [valid],
    )
    assert result.decision == "block"
    assert result.reason == "SOURCE_CONTENT_ATTESTATION_FAILED"
    assert calls == []


def test_revoked_source_permission_fails_closed_at_layer2(provenance):
    _, verifier, valid, _ = provenance

    class RevokingGuard(SyntheticAllowingGuard):
        def check_output(self, **kwargs):
            self.output_calls += 1
            return {"decision": "block", "reason": "LAYER2_ACCESS_REVOKED"}

    guard = RevokingGuard()
    result = ProtectedRAG(guard, provenance_verifier=verifier).run(
        employee_token="synthetic", application_id="rag-app", retrieved=[valid],
        generate=lambda docs: "PRIVATE ANSWER", source_trace=lambda: [valid],
    )
    assert result.decision == "block"
    assert result.response is None
    assert result.reason == "LAYER2_ACCESS_REVOKED"
    assert guard.output_calls == 1


def test_guard_outage_fails_closed_without_releasing_buffered_output(provenance):
    _, verifier, valid, _ = provenance

    class UnavailableGuard(SyntheticAllowingGuard):
        def filter_resources(self, **kwargs):
            raise httpx.ConnectError("synthetic outage")

    result = ProtectedRAG(UnavailableGuard(), provenance_verifier=verifier).run(
        employee_token="synthetic", application_id="rag-app", retrieved=[valid],
        generate=lambda docs: "MUST NOT RELEASE", source_trace=lambda: [valid],
    )
    assert result.decision == "block"
    assert result.response is None
    assert result.reason == "GUARD_REQUEST_FAILED"


def test_same_chunk_identity_cannot_carry_substituted_bytes(provenance):
    _, verifier, valid, _ = provenance
    forged = replace(valid, content="SYNTHETIC PRIVATE PAYROLL SECRET")
    result = ProtectedRAG(SyntheticAllowingGuard(), provenance_verifier=verifier).run(
        employee_token="synthetic", application_id="rag-app", retrieved=[forged],
        generate=lambda docs: docs[0].content, source_trace=lambda: [forged],
    )
    assert result.decision == "block"
    assert result.reason == "SOURCE_CONTENT_ATTESTATION_FAILED"
    assert result.response is None
