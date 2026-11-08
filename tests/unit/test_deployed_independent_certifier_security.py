from __future__ import annotations

import base64
import json
from pathlib import Path
import pytest
from scripts.certifier import bootstrap_independent_host_ssm as b

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy/certifier/independent"


def test_deployment_roles_named_and_instance_remains_private():
    t=json.loads((DEPLOY/"isolated-certifier-stack.json").read_text())["Resources"]
    assert t["CertifierBaseRole"]["Properties"]["RoleName"]=="AccessProofIndependentCertifierBase2026"
    assert t["CertifierExecutionRole"]["Properties"]["RoleName"]=="AccessProofIndependentCertifierExec2026"
    assert t["CertifierInstanceProfile"]["Properties"]["InstanceProfileName"]=="AccessProofIndependentCertifier2026"
    assert t["CertifierInstance"]["Properties"]["NetworkInterfaces"][0]["AssociatePublicIpAddress"] is False


def test_operator_role_bounded_to_new_host_and_deny_prod_commands():
    p=json.loads((DEPLOY/"bootstrap-scoped-role-policy.json").read_text())
    by={s["Sid"]:s for s in p["Statement"]}
    cmd=by["RunApprovedDiagnosticsOnlyOnNewIsolatedCertifierHost"]
    assert "arn:aws:ec2:eu-north-1:102076848988:instance/i-0af8a03948e7ba058" in cmd["Resource"]
    assert "arn:aws:ec2:eu-north-1:102076848988:instance/i-0c11427d4d9c1b438" not in cmd["Resource"]
    assert "arn:aws:ec2:eu-north-1:102076848988:instance/i-0e6d2256a1e5a6f67" not in cmd["Resource"]
    assert all("kms:Sign" not in json.dumps(s) for s in p["Statement"])
    assert "iam:CreateUser" in by["NoProductionCommandsOrUnrelatedIam"]["Action"]


def test_iam_user_access_only_assumes_restricted_infra_role():
    p=json.loads((DEPLOY/"iam-user-role-assumption-only.json").read_text())
    assert p["Statement"] == [{
        "Sid":"AssumeOnlyPurposeScopedCertifierInfrastructureOperator",
        "Effect":"Allow","Action":"sts:AssumeRole",
        "Resource":"arn:aws:iam::102076848988:role/AccessProofIndependentInfraBootstrap"
    }]


def test_public_key_candidate_matches_wire_format_without_signing_material():
    candidate=json.loads((DEPLOY/"candidate-public-key.json").read_text())
    assert candidate["key_id"]=="kms-certifier-2026-11"
    assert candidate["kms_key_arn"].endswith("0f040c1c-afc8-4227-9f9f-18aa014c5f10")
    raw=base64.urlsafe_b64decode(candidate["public_key_base64url"]+"===")
    assert len(raw)==32
    assert candidate["prod_trust_status"]=="NOT_REGISTERED"
    assert candidate["signing_enabled"] is False
    assert not any("private" in k.lower() for k in candidate)


def test_hardened_preflight_home_dedicated_for_dynamic_user():
    src=(DEPLOY/"bootstrap_readonly_host.sh").read_text()
    assert "DynamicUser=yes" in src
    assert "RuntimeDirectory=accessproof-independent-certifier" in src
    assert "Environment=HOME=/run/accessproof-independent-certifier" in src
    assert "AWS_SHARED_CREDENTIALS_FILE=/dev/null" in src
    assert "ProtectSystem=strict" in src
    assert "Environment=AWS_PROFILE=accessproof-certifier" in src


def test_reinstaller_rejects_root_or_unknown_operator_without_provisioning(monkeypatch):
    seen=[]
    def aws(*args):
        seen.append(args)
        return {"Arn":"arn:aws:iam::102076848988:root"}
    monkeypatch.setattr(b,"aws",aws)
    with pytest.raises(RuntimeError,match="SCOPED_CERTIFIER_OPERATOR_REQUIRED"):
        b.verify_target()
    assert seen==[("sts","get-caller-identity")]


def test_reinstaller_transfers_only_public_code_and_checks_hashes():
    c=b.make_commands("i-0af8a03948e7ba058",
                      "arn:aws:iam::102076848988:role/AccessProofIndependentCertifierExec2026",
                      "arn:aws:kms:eu-north-1:102076848988:key/0f040c1c-afc8-4227-9f9f-18aa014c5f10")
    assert len(c)>4 and all(len(x)<3900 for x in c)
    assert sum("sha256sum -c" in line for line in c)==2
    assert not any(".pem" in line or "refresh_token" in line for line in c)
    assert any("bootstrap_readonly_host.sh" in line for line in c)
