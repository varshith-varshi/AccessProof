from packages.rag_sdk import adapter_registry


def test_registry_only_marks_enforcement_adapters_as_protect_capable() -> None:
    registry = {item["id"]: item for item in adapter_registry()}
    assert registry["langchain-python"]["pre_generation_filtering"] is True
    assert registry["llamaindex-python"]["output_verification"] is True
    assert registry["generic-http"]["pre_generation_filtering"] is False
    assert registry["generic-http"]["protect_mode"] is False

