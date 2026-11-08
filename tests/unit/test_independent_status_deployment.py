"""The read-only watcher can be reinstalled after an in-place stack update."""
from __future__ import annotations

import json
import sys
from pathlib import Path
import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"scripts/certifier"))
import bootstrap_independent_host_ssm as h
import bootstrap_independent_status_ssm as b


INSTANCE="i-0af8a03948e7ba058"
ROLE="arn:aws:iam::102076848988:role/AccessProofIndependentCertifierExec2026"
KEY="arn:aws:kms:eu-north-1:102076848988:key/0f040c1c-afc8-4227-9f9f-18aa014c5f10"


def test_certifier_stack_update_complete_is_valid_for_reinstall(monkeypatch):
    def aws(*args):
        if args[:2]==("sts","get-caller-identity"):
            return {"Arn":"arn:aws:sts::102076848988:assumed-role/AccessProofIndependentInfraBootstrap/synthetic"}
        if args[:2]==("cloudformation","describe-stacks"):
            return {"Stacks":[{"StackStatus":"UPDATE_COMPLETE",
                              "Outputs":[{"OutputKey":k,"OutputValue":v} for k,v in (
                                ("CertifierInstanceId",INSTANCE),("CertifierExecutionRoleArn",ROLE),
                                ("CertifierSigningKeyArn",KEY),
                                ("CertifierPrivateSubnetId","subnet-0142f48636f6e35c7"))]}]}
        if args[:2]==("ec2","describe-instances"):
            return {"Reservations":[{"Instances":[{
                "State":{"Name":"running"},"SubnetId":"subnet-0142f48636f6e35c7",
                "VpcId":"vpc-0be4dc69e57c09b2f"}]}]}
        if args[:2]==("ssm","describe-instance-information"):
            return {"InstanceInformationList":[{"InstanceId":INSTANCE,"PingStatus":"Online"}]}
        raise AssertionError("Unexpected AWS call")
    monkeypatch.setattr(h,"aws",aws)
    assert h.verify_target()==(INSTANCE,ROLE,KEY)


def test_active_stack_must_not_be_in_progress(monkeypatch):
    monkeypatch.setattr(h,"aws",lambda *args:
        {"Arn":"arn:aws:sts::102076848988:assumed-role/AccessProofIndependentInfraBootstrap/synthetic"}
        if args[:2]==("sts","get-caller-identity")
        else {"Stacks":[{"StackStatus":"UPDATE_IN_PROGRESS"}]})
    with pytest.raises(RuntimeError, match="INDEPENDENT_STACK_NOT_COMPLETE"):
        h.verify_target()


def test_installer_never_copies_signer_employee_tokens_or_imports():
    c=b.make_commands(INSTANCE,ROLE,KEY)
    assert any("sha256sum -c" in x for x in c)
    assert sum("sha256sum -c" in x for x in c)==2
    assert all(len(x)<3900 for x in c)
    assert not any("refresh_token" in x or ".sock" in x or "kms:Sign" in x
                   or "ProductionImport" in x for x in c)
    assert any("install_status_watcher.sh" in x for x in c)
