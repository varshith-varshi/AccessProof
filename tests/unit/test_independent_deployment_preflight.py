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
