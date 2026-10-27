"""Only the signed-retrieval Gateway is a customer-facing V1 integration."""
from packages.rag_core import adapter_registry


def test_registry_only_exposes_gateway_for_customer_installation() -> None:
    entries = adapter_registry()
    assert len(entries) == 1
    assert entries[0]["id"] == "accessproof-gateway"
    assert entries[0]["pre_generation_filtering"] is True
    assert entries[0]["output_verification"] is True
    assert entries[0]["protect_mode"] is True
    assert entries[0]["status"] == "AVAILABLE"
    assert "signed" not in entries[0]["installation"].lower() or "Gateway" in entries[0]["installation"]
    assert not any("sdk" in item["installation"].lower() for item in entries)
