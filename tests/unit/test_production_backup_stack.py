"""Guard rails for reviewed, *undeployed* encrypted production backups."""
from pathlib import Path

import yaml


STACK = (
    Path(__file__).resolve().parents[2]
    / "deploy/backup/isolated-postgres-s3-stack.yaml"
)


class CloudFormationLoader(yaml.SafeLoader):
    pass


def _construct_cfn(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {tag_suffix: value}


CloudFormationLoader.add_multi_constructor("!", _construct_cfn)


def template():
    return yaml.load(STACK.read_text(), Loader=CloudFormationLoader)


def role_actions(role):
    blocks = role["Properties"]["Policies"]
    return [
        action
        for policy in blocks
        for statement in policy["PolicyDocument"]["Statement"]
        for action in (
            [statement["Action"]] if isinstance(statement["Action"], str)
            else statement["Action"]
        )
    ]


def test_backup_storage_encrypted_locked_and_not_public():
    data = template()
    r = data["Resources"]
    bucket = r["BackupBucket"]["Properties"]
    assert bucket["PublicAccessBlockConfiguration"] == {
        "BlockPublicAcls": True, "BlockPublicPolicy": True,
        "IgnorePublicAcls": True, "RestrictPublicBuckets": True,
    }
    assert bucket["VersioningConfiguration"]["Status"] == "Enabled"
    assert bucket["ObjectLockEnabled"] is True
    retention = bucket["ObjectLockConfiguration"]["Rule"]["DefaultRetention"]
    assert retention == {"Mode": "GOVERNANCE", "Days": {"Ref": "RetentionDays"}}
    assert data["Parameters"]["RetentionDays"]["MinValue"] >= 30
    encryption = bucket["BucketEncryption"]["ServerSideEncryptionConfiguration"][0]
    assert encryption["ServerSideEncryptionByDefault"]["SSEAlgorithm"] == "aws:kms"
    assert encryption["ServerSideEncryptionByDefault"]["KMSMasterKeyID"] == {
        "GetAtt": "BackupKmsKey.Arn"
    }
    assert r["BackupBucket"]["DeletionPolicy"] == "Retain"
    assert r["BackupKmsKey"]["DeletionPolicy"] == "Retain"
    assert r["BackupKmsKey"]["Properties"]["KeyUsage"] == "ENCRYPT_DECRYPT"
    assert r["BackupKmsKey"]["Properties"]["EnableKeyRotation"] is True


def test_iam_scope_and_separate_backup_restore_identities():
    r = template()["Resources"]
    writer = r["BackupWriterRole"]
    reader = r["IsolatedRestoreReaderRole"]
    assert writer["Properties"]["AssumeRolePolicyDocument"]["Statement"][0][
        "Principal"]["AWS"] == {"Ref": "ProductionInstanceRoleArn"}
    assert reader["Properties"]["AssumeRolePolicyDocument"]["Statement"][0][
        "Principal"]["AWS"] == {"Ref": "IsolatedRestoreOperatorRoleArn"}
    writer_actions, reader_actions = set(role_actions(writer)), set(role_actions(reader))
    assert "s3:PutObject" in writer_actions
    assert "s3:GetObject" in reader_actions
    assert "s3:PutObject" not in reader_actions
    for actions in (writer_actions, reader_actions):
        assert not (actions & {"s3:DeleteObject", "s3:*", "kms:*", "kms:Sign", "iam:*"})
        assert "*" not in actions
    assert "kms:Decrypt" in reader_actions
    assert "kms:GenerateDataKey" in writer_actions
    assert "kms:GenerateDataKey" not in reader_actions


def test_bucket_policy_blocks_tls_bypass_wrong_encryption_and_unapproved_writes():
    statements = template()["Resources"]["BackupBucketPolicy"]["Properties"][
        "PolicyDocument"]["Statement"]
    names = {entry["Sid"] for entry in statements}
    assert names == {
        "RequireTLS", "RequireExplicitKMSOnUpload",
        "RequirePinnedKMSOnUpload", "OnlyApprovedWriterMayUpload"
    }
    assert all(statement["Effect"] == "Deny" for statement in statements)
    assert all(statement["Principal"] == "*" for statement in statements)
    assert "aws:PrincipalArn" in statements[-1]["Condition"]["StringNotEquals"]
