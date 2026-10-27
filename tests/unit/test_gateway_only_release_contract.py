"""The shipped V1 must not silently reinstate customer RAG SDK integration."""
from pathlib import Path

import pytest
from pydantic import ValidationError

from apps.api.accessproof_api.schemas import AIApplicationCreate
from packages.rag_core import ProtectedRAG, SourceAttestationVerifier
from packages.rag_core.registry import adapter_registry


ROOT = Path(__file__).resolve().parents[2]


def test_gateway_is_the_only_new_application_registration() -> None:
    assert AIApplicationCreate(application_id="staff-rag", name="Staff RAG").adapter_type == "accessproof-gateway"
    for obsolete in (
        "generic-python", "generic-typescript", "generic-http",
        "langchain-python", "langchain-typescript",
        "llamaindex-python", "haystack-python",
    ):
        with pytest.raises(ValidationError):
            AIApplicationCreate(application_id="staff-rag", name="Staff RAG", adapter_type=obsolete)


def test_customer_sdk_packages_are_not_shipped() -> None:
    assert not (ROOT / "packages" / "rag_sdk").exists()
    assert not (ROOT / "packages" / "rag-sdk-typescript").exists()
    assert not (ROOT / "packages" / "rag_core" / "adapters.py").exists()
    assert ProtectedRAG is not None
    assert SourceAttestationVerifier is not None


def test_gateway_catalog_exposes_one_integrated_protection_boundary() -> None:
    entries = adapter_registry()
    assert len(entries) == 1
    profile = entries[0]
    assert profile["id"] == "accessproof-gateway"
    assert profile["pre_generation_filtering"] is True
    assert profile["output_verification"] is True
    assert profile["protect_mode"] is True
    assert "attest" in profile["limitation"].lower()


def test_customer_ui_does_not_offer_sdk_integration() -> None:
    integration_page = (ROOT / "web-v2" / "app" / "integrations" / "page.tsx").read_text()
    app_page = (ROOT / "web-v2" / "app" / "applications" / "page.tsx").read_text()
    for text in ("LangChain", "LlamaIndex", "Haystack", "Generic Python", "RAG SDK"):
        assert text not in integration_page
        assert text not in app_page
    assert "Integration adapter<select" not in app_page
    assert "AccessProof Gateway" in integration_page
    assert 'adapter_type: "accessproof-gateway"' in app_page
