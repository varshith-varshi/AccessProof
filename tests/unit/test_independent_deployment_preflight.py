"""Preflight is read-only and cannot bless root or silently deploy."""
from __future__ import annotations

from scripts.certifier import independent_deployment_preflight as p


def test_root_profile_is_rejected_without_aws_calls(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "default")
    monkeypatch.setattr(p, "cli", lambda *a: (_ for _ in ()).throw(AssertionError("AWS call")))
    report = p.preflight()
    assert report["ready"] is False and report["deployed"] is False
    assert report["blocker"] == "EXPLICIT_NONROOT_AWS_PROFILE_REQUIRED"


def test_root_sts_identity_is_rejected(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "separate-infrastructure-admin")
    for name in ("AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN",
                 "AWS_SECURITY_TOKEN","AWS_WEB_IDENTITY_TOKEN_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(p, "cli", lambda *a:(True,{"Arn":"arn:aws:iam::102076848988:root"}))
    report = p.preflight()
    assert report["blocker"] == "NONROOT_IDENTITY_REQUIRED"
    assert report["checks"]["nonroot_identity"] is False


def test_scoped_role_denied_cloudformation_stays_blocked(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-certifier")
    for name in ("AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN",
                 "AWS_SECURITY_TOKEN","AWS_WEB_IDENTITY_TOKEN_FILE"):
        monkeypatch.delenv(name, raising=False)

    def fake_cli(*args):
        if args[:2] == ("sts", "get-caller-identity"):
            return True, {"Arn":"arn:aws:sts::102076848988:assumed-role/accessproof-certifier/synthetic"}
        return False, "ACCESS_DENIED"

    monkeypatch.setattr(p, "cli", fake_cli)
    report = p.preflight()
    assert report["ready"] is False
    assert report["deployed"] is False
    assert report["checks"]["cloudformation_validate_authorized"] is False


def test_authorized_read_only_validation_never_claims_deployed(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE","limited-infrastructure-deployer")
    for name in ("AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN",
                 "AWS_SECURITY_TOKEN","AWS_WEB_IDENTITY_TOKEN_FILE"):
        monkeypatch.delenv(name, raising=False)

    def fake_cli(*args):
        if args[:2] == ("sts", "get-caller-identity"):
            return True, {"Arn":"arn:aws:sts::102076848988:assumed-role/limited-infrastructure-deployer/synthetic"}
        if args[:2] == ("cloudformation", "validate-template"):
            return True, {"Description":"safe"}
        if args[:2] == ("ec2", "describe-subnets"):
            return True, {"Subnets":[{"VpcId":p.VPC,"AvailabilityZone":p.ZONE}]}
        if args[:2] == ("cloudformation", "list-stacks"):
            return True, {"StackSummaries":[]}
        raise AssertionError("unexpected call")

    monkeypatch.setattr(p, "cli", fake_cli)
    report = p.preflight()
    assert report["checks"]["cloudformation_validate_authorized"] is True
    assert report["checks"]["public_subnet_matches_review"] is True
    assert report["ready"] is False and report["deployed"] is False
    assert report["blocker"] == "DEPLOYMENT_REQUIRES_SCOPED_INFRASTRUCTURE_ADMIN_REVIEW"


def _deployed_stack_cli(*, status="UPDATE_COMPLETE", include_key=True, deny_describe=False):
    def fake_cli(*args):
        if args[:2] == ("sts", "get-caller-identity"):
            return True, {"Arn": "arn:aws:sts::102076848988:assumed-role/scoped-admin/test"}
        if args[:2] == ("cloudformation", "validate-template"):
            return True, {"Description": "validated"}
        if args[:2] == ("ec2", "describe-subnets"):
            return True, {"Subnets": [{"VpcId": p.VPC, "AvailabilityZone": p.ZONE}]}
        if args[:2] == ("cloudformation", "list-stacks"):
            return True, {"StackSummaries": [
                {"StackName": p.TARGET, "StackStatus": status},
            ]}
        if args[:2] == ("cloudformation", "describe-stacks"):
            if deny_describe:
                return False, "ACCESS_DENIED"
            keys = ["CertifierInstanceId", "CertifierExecutionRoleArn"]
            if include_key:
                keys.append("CertifierSigningKeyArn")
            return True, {"Stacks": [
                {"StackName": p.TARGET, "StackStatus": status,
                 "Outputs": [{"OutputKey": name, "OutputValue": "placeholder"}
                             for name in keys]},
            ]}
        raise AssertionError(f"Unexpected AWS action: {args}")
    return fake_cli


def test_existing_complete_stack_detected_without_redeployment(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-infra-scoped")
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                 "AWS_SECURITY_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(p, "cli", _deployed_stack_cli())
    report = p.preflight()
    assert report["existing_stack_status"] == "UPDATE_COMPLETE"
    assert report["deployed"] is True
    assert report["ready"] is False
    assert report["signing_enabled"] is False
    assert report["renewal_independent"] is False
    assert report["blocker"] == "EXISTING_CERTIFIER_STACK_REQUIRES_APPROVED_SIGNING_CUTOVER"
    assert "command_for_authorized_admin" not in report


def test_existing_stack_without_trusted_outputs_fails_closed(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-infra-scoped")
    monkeypatch.setattr(p, "cli", _deployed_stack_cli(include_key=False))
    report = p.preflight()
    assert report["deployed"] is False
    assert report["blocker"] == "EXISTING_CERTIFIER_STACK_REQUIRES_REVIEW"
    assert "command_for_authorized_admin" not in report


def test_existing_stack_rollback_state_fails_closed(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-infra-scoped")
    monkeypatch.setattr(p, "cli", _deployed_stack_cli(status="UPDATE_ROLLBACK_COMPLETE"))
    report = p.preflight()
    assert report["deployed"] is False
    assert report["blocker"] == "EXISTING_CERTIFIER_STACK_REQUIRES_REVIEW"
    assert "command_for_authorized_admin" not in report


def test_existing_stack_denied_details_never_suggests_second_deploy(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-infra-scoped")
    monkeypatch.setattr(p, "cli", _deployed_stack_cli(deny_describe=True))
    report = p.preflight()
    assert report["ready"] is False and report["deployed"] is False
    assert report["blocker"] == "EXISTING_CERTIFIER_STACK_REQUIRES_REVIEW"
    assert "command_for_authorized_admin" not in report
