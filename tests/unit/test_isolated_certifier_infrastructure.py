"""Security invariants of the admin-only, observer-first CloudFormation stack."""
from __future__ import annotations

import json
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[2] / "deploy/certifier/independent/isolated-certifier-stack.json"


def test_stack_isolated_private_encrypted_and_imdsv2():
    stack = json.loads(TEMPLATE.read_text())
    resources = stack["Resources"]
    instance = resources["CertifierInstance"]["Properties"]
    assert instance["MetadataOptions"]["HttpTokens"] == "required"
    assert instance["MetadataOptions"]["HttpPutResponseHopLimit"] == 1
    assert all(nic["AssociatePublicIpAddress"] is False for nic in instance["NetworkInterfaces"])
    assert all(nic["DeleteOnTermination"] is True for nic in instance["NetworkInterfaces"])
    assert instance["BlockDeviceMappings"][0]["Ebs"]["Encrypted"] is True
    assert instance["IamInstanceProfile"] == {"Ref": "CertifierInstanceProfile"}
    assert "PRIVATE KEY" not in str(instance)
    assert "ACCESS_KEY" not in str(instance)


def test_no_inbound_listener_and_only_https_egress():
    sg = json.loads(TEMPLATE.read_text())["Resources"]["CertifierSecurityGroup"]["Properties"]
    assert "SecurityGroupIngress" not in sg
    assert sg["SecurityGroupEgress"] == [{
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "CidrIp": "0.0.0.0/0",
        "Description": "HTTPS to required AWS and authorized identity services, restrict at NAT/proxy",
    }]


def test_new_ed25519_key_cannot_sign_before_trust_approval():
    resources = json.loads(TEMPLATE.read_text())["Resources"]
    key = resources["CertifierSigningKey"]
    assert key["Properties"]["KeyUsage"] == "SIGN_VERIFY"
    assert key["Properties"]["KeySpec"] == "ECC_NIST_EDWARDS25519"
    assert key["DeletionPolicy"] == "Retain"
    assert resources["CertifierExecutionRole"]["Properties"]["Policies"][0][
        "PolicyDocument"]["Statement"][0]["Action"] == ["kms:GetPublicKey", "kms:DescribeKey"]
    assert all("kms:Sign" not in json.dumps(x) for x in (
        resources["CertifierExecutionRole"], resources["CertifierBaseRole"],
        resources["AllowBaseRoleToAssumeExecution"],
    ))
    assert not any("ProductionImport" in json.dumps(x) for x in (
        resources["CertifierExecutionRole"], resources["CertifierBaseRole"],
    ))


def test_assume_role_chain_is_restricted_and_no_new_service_is_enabled():
    resources = json.loads(TEMPLATE.read_text())["Resources"]
    assert resources["CertifierExecutionRole"]["Properties"]["AssumeRolePolicyDocument"][
        "Statement"][0]["Principal"]["AWS"] == {"Fn::GetAtt": ["CertifierBaseRole", "Arn"]}
    assert resources["AllowBaseRoleToAssumeExecution"]["Properties"]["PolicyDocument"][
        "Statement"][0]["Resource"] == {"Fn::GetAtt": ["CertifierExecutionRole", "Arn"]}
    assert resources["CertifierInstance"]["Properties"]["UserData"]["Fn::Base64"].count(
        "CERTIFIER_INACTIVE_BY_DEFAULT"
    ) == 1
    resources_or_output = json.dumps(json.loads(TEMPLATE.read_text())["Outputs"])
    assert "OBSERVER_ONLY_NOT_CERTIFIED" in resources_or_output
