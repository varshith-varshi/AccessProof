"""Cross-tenant and live-evidence safety regressions for customer certification."""
from __future__ import annotations

import socket
import json
from pathlib import Path

import pytest

from scripts.certifier.customer_certification import (
    PROFILE_FIELDS,
    CANARY_RIGHTS,
    RegistrationError,
    source_preflight,
    validate_registration,
)

ORG = "12345678-1111-4111-8111-123456789abc"
SOURCE = "23456789-2222-4222-8222-23456789abcd"
TENANT = "34567890-3333-4333-8333-34567890abcd"
ALICE = "45678901-4444-4444-8444-45678901abcd"
BOB = "56789012-5555-4555-8555-56789012abcd"
SITE = "https://customer.sharepoint.com/sites/AccessProof-Canaries"


def fixture(tmp: Path) -> tuple[Path, Path]:
    overrides = {module: {key: None for key in keys} for module, keys in PROFILE_FIELDS.items()}
    values = {
        "renew_source_certificate": {"ORG": ORG, "SOURCE": SOURCE, "APP": "customer-rag",
                                     "GUARD_CONTAINER": "guard-customer", "SOCKS": {
                                         "alice": str(tmp / "alice.sock"), "bob": str(tmp / "bob.sock")}},
        "employee_identity": {"TENANT": TENANT, "SITE": SITE,
                              "ISSUER": f"https://login.microsoftonline.com/{TENANT}/v2.0"},
        "sharepoint_effective_matrix": {"ORG": ORG, "SOURCE": SOURCE,
                                        "SITE": SITE, "EXPECTED": CANARY_RIGHTS},
        "layer1_matrix": {"ORG": ORG, "SRC": SOURCE, "APP": "customer-rag",
                          "EXPECT": {a: {doc: "ALLOW" if allowed else "DENY"
                                        for doc, allowed in docs.items()}
                                     for a, docs in CANARY_RIGHTS.items()}},
        "rag_e2e": {"ORG": ORG, "SOURCE": SOURCE, "APP": "customer-rag"},
        "revocation_trial": {"ORG": ORG, "SOURCE": SOURCE, "APP": "customer-rag"},
    }
    for module, additional in values.items():
        overrides[module].update(additional)
    profile = tmp / "profile.json"
    profile.write_text(json.dumps(overrides))
    profile.chmod(0o600)
    registration = tmp / "registration.json"
    data = {
        "schema": "accessproof.source_certification_registration/v1",
        "organization_id": ORG, "source_id": SOURCE, "tenant_id": TENANT,
        "application_id": "customer-rag", "scope_digest": "a" * 64,
        "gateway_service": "accessproof-gateway",
        "profile_file": str(profile), "canary": {
            "site_url": SITE, "mutation_authorized": True,
            "employee_object_ids": {"alice": ALICE, "bob": BOB},
        },
    }
    registration.write_text(json.dumps(data))
    registration.chmod(0o600)
    return registration, profile


def test_source_specific_registration_requires_own_live_profiles(tmp_path):
    reg, _ = validate_registration(fixture(tmp_path)[0])
    assert reg["source_id"] == SOURCE
    assert reg["employee_object_ids"]["bob"] == BOB


def test_reference_profile_cannot_be_relabelled_as_customer_source(tmp_path):
    registration, profile = fixture(tmp_path)
    data = json.loads(profile.read_text())
    data["sharepoint_effective_matrix"]["SOURCE"] = "2fa9562b-b765-4098-bebf-222ea53ec667"
    profile.write_text(json.dumps(data))
    with pytest.raises(RegistrationError, match="PROFILE_CROSS_SOURCE_REUSE"):
        validate_registration(registration)


def test_certificate_does_not_run_without_explicit_canary_consent(tmp_path):
    registration, _ = fixture(tmp_path)
    data = json.loads(registration.read_text())
    data["canary"]["mutation_authorized"] = False
    registration.write_text(json.dumps(data))
    with pytest.raises(RegistrationError, match="CUSTOMER_TEST_CANARY_APPROVAL_REQUIRED"):
        validate_registration(registration)


def test_cross_tenant_employee_oid_cannot_be_substituted(tmp_path):
    registration, _ = fixture(tmp_path)
    data = json.loads(registration.read_text())
    data["canary"]["employee_object_ids"]["bob"] = ALICE
    registration.write_text(json.dumps(data))
    with pytest.raises(RegistrationError, match="TEST_EMPLOYEES_NOT_DISTINCT"):
        validate_registration(registration)


def test_registration_file_must_be_private(tmp_path):
    registration, _ = fixture(tmp_path)
    registration.chmod(0o644)
    with pytest.raises(RegistrationError, match="PRIVATE_CONFIGURATION_PERMISSIONS"):
        validate_registration(registration)


def test_remote_scope_and_identity_mismatch_block_certification(tmp_path, monkeypatch):
    import scripts.certifier.customer_certification as cc
    reg, profile = validate_registration(fixture(tmp_path)[0])
    monkeypatch.setattr(cc, "_employee_claims", lambda sock: {
        "graph_me_oid_match": True,
        "id_token_claims": {"oid": ALICE if sock.name == "alice.sock" else BOB, "tid": TENANT},
    })
    listener_a = socket.socket(socket.AF_UNIX)
    listener_b = socket.socket(socket.AF_UNIX)
    listener_a.bind(str(tmp_path / "alice.sock"))
    listener_b.bind(str(tmp_path / "bob.sock"))
    monkeypatch.setenv("AWS_PROFILE", "accessproof-certifier")
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(name, raising=False)

    def readonly(operation, **kwargs):
        if operation == "source_scope":
            return json.dumps({"profile": "sharepoint_list_item_effective",
                               "scope_digest": "b" * 64})
        if operation == "sync_cursors":
            return "acl:connected,directory:connected"
        if operation == "identity_bindings":
            return json.dumps([{"oidc_subject_oid": ALICE, "method": "directory_verified",
                                "status": "VERIFIED", "oid_equals_source_principal": True},
                               {"oidc_subject_oid": BOB, "method": "directory_verified",
                                "status": "VERIFIED", "oid_equals_source_principal": True}])
        raise AssertionError(operation)

    try:
        errors = source_preflight(reg, profile, readonly)
        assert "SOURCE_SCOPE_CHANGED" in errors
    finally:
        listener_a.close()
        listener_b.close()


def test_evidence_builder_rejects_wrong_source_even_with_pass_status(tmp_path, monkeypatch):
    import scripts.live.build_certificate_evidence as builder
    evidence = tmp_path / "sharepoint-effective-matrix.json"
    evidence.write_text(json.dumps({
        "schema": "accessproof.sharepoint_effective_matrix/v1",
        "organization_id": ORG,
        "source_id": "2fa9562b-b765-4098-bebf-222ea53ec667",
        "pass": True, "results": [],
    }))
    monkeypatch.setenv("AP_SOURCE_BOUND_EVIDENCE", "1")
    monkeypatch.setattr(builder, "_FRESH_DIR", tmp_path)
    monkeypatch.setattr(builder, "_BOUND_ORG", ORG)
    monkeypatch.setattr(builder, "_BOUND_SOURCE", SOURCE)
    with pytest.raises(ValueError, match="EVIDENCE_ARTIFACT_SOURCE_MISMATCH"):
        builder.load("sharepoint-effective-matrix.json")
