"""Metadata-only lineage cannot attest actual content.

Protect release requires a trusted source-content attestation. A resource ID
alone proves only which ACL entry was checked, never which bytes the generator
actually received.
"""
from packages.rag_sdk.protection import ProtectedRAG, RetrievedResource


class MetadataOnlyGuard:
    def __init__(self) -> None:
        self.output_calls = 0

    def filter_resources(self, *, resources, **_):
        # Synthetic correct Guard: source ACL says "public-file" is readable.
        return {
            "decision": "allow", "mode": "protect", "decision_id": "synthetic-decision",
            "allowed": [{"source_id": "drive", "resource_id": "public-file", "chunk_ids": []}],
        }

    def check_output(self, **_):
        # Layer 2 only receives declared metadata, not attested bytes.
        self.output_calls += 1
        return {"decision": "allow", "reason": "TRUSTED_PROVENANCE_VALID"}


def test_forged_authorized_metadata_must_not_release_unattributed_secret_bytes():
    # Untrusted vector-store text is from an unauthorized source, but claims
    # the identity of a file that ACL enforcement legitimately permits.
    forged = RetrievedResource(
        source_id="drive", resource_id="public-file",
        content="SYNTHETIC PRIVATE PAYROLL SECRET",
    )
    guard = MetadataOnlyGuard()
    generated: list[list[RetrievedResource]] = []
    result = ProtectedRAG(guard).run(
        employee_token="synthetic", application_id="app",
        retrieved=[forged],
        generate=lambda documents: generated.append(documents) or documents[0].content,
        source_trace=lambda: [
            RetrievedResource(source_id="drive", resource_id="public-file")
        ],
    )
    assert result.response is None and result.decision == "block"
    assert result.reason == "SOURCE_CONTENT_ATTESTATION_REQUIRED"
    assert result.certification_eligible is False
    assert generated == []
    assert guard.output_calls == 0


def test_explicit_legacy_metadata_mode_is_never_certification_eligible():
    """The compatibility escape hatch must be explicit and permanently unmarked."""
    forged = RetrievedResource(
        source_id="drive", resource_id="public-file",
        content="LEGACY METADATA-ONLY CONTENT",
    )
    result = ProtectedRAG(MetadataOnlyGuard(), allow_unattested_metadata=True).run(
        employee_token="synthetic", application_id="app",
        retrieved=[forged],
        generate=lambda documents: documents[0].content,
        source_trace=lambda: [
            RetrievedResource(source_id="drive", resource_id="public-file")
        ],
    )
    assert result.decision == "allow"
    assert result.response == "LEGACY METADATA-ONLY CONTENT"
    assert result.provenance_level == "UNATTESTED_METADATA_ONLY"
    assert result.certification_eligible is False
