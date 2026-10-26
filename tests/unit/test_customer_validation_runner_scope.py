"""The release validation runner must not refer to retired SDK tests."""
from customer_simulation.run_full_enterprise_validation import CHECKS, ROOT


def test_enterprise_validation_runner_references_only_existing_test_modules():
    for stage, paths in CHECKS:
        assert paths, stage
        for relative in paths:
            assert (ROOT / relative).exists(), (stage, relative)


def test_gateway_only_security_release_stage_replaces_public_sdk_suite():
    stages = dict(CHECKS)
    assert "gateway_source_integrity_and_release" in stages
    assert not any("sdk" in name for name in stages)
    paths = stages["gateway_source_integrity_and_release"]
    assert "tests/unit/test_gateway_network_boundary.py" in paths
    assert "tests/security/test_gateway_upstream_transport.py" in paths
    assert "tests/security/test_gateway_scoped_readiness.py" in paths
    assert not any("rag_adapters" in item or "test_sdk_" in item for item in paths)
