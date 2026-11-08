"""AWS disaster recovery audit cannot mistake missing permissions for safety."""
from __future__ import annotations

from scripts.drills import production_backup_readiness as dr


def _mock_aws(*, backup_visible: bool, encrypted: bool = False,
              backup_present: bool = False):
    calls: list[tuple[str, ...]] = []

    def fake(*args: str):
        calls.append(args)
        if args[:2] == ("sts", "get-caller-identity"):
            return True, {"Arn": "arn:aws:sts::102076848988:assumed-role/scoped/dr"}
        if args[:2] == ("ec2", "describe-instances"):
            return True, {"Reservations": [{"Instances": [
                {"InstanceId": dr.INSTANCE, "BlockDeviceMappings": [
                    {"Ebs": {"VolumeId": "vol-allowed"}}
                ]}
            ]}]}
        if args[:2] == ("ec2", "describe-volumes"):
            return True, {"Volumes": [{"VolumeId": "vol-allowed",
                                      "Encrypted": encrypted}]}
        if args[0] == "backup":
            if not backup_visible:
                return False, "ACCESS_DENIED"
            if args[1] == "list-backup-plans":
                return True, {"BackupPlansList": ([{"BackupPlanId": "plan1"}]
                                                  if backup_present else [])}
            if args[1] == "list-backup-vaults":
                return True, {"BackupVaultList": ([{"BackupVaultName": "vault1"}]
                                                 if backup_present else [])}
            if args[1] == "list-recovery-points-by-resource":
                return True, {"RecoveryPoints": ([{"RecoveryPointArn": "point1"}]
                                                if backup_present else [])}
        raise AssertionError(f"unexpected action: {args}")
    return fake, calls


def test_root_profile_rejected_without_any_aws_calls(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "default")
    monkeypatch.setattr(dr, "aws", lambda *args: (_ for _ in ()).throw(
        AssertionError("must not use AWS as root")))
    report = dr.audit()
    assert report["ready"] is False
    assert report["blocker"] == "EXPLICIT_NONROOT_PROFILE_REQUIRED"


def test_static_credential_override_rejected_without_aws_calls(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-infra-scoped")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "no-real-secret")
    monkeypatch.setattr(dr, "aws", lambda *args: (_ for _ in ()).throw(
        AssertionError("must not use static AWS credentials")))
    assert dr.audit()["blocker"] == "EXPLICIT_NONROOT_PROFILE_REQUIRED"


def test_access_denied_is_unobservable_not_no_backups(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-infra-scoped")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    fake, calls = _mock_aws(backup_visible=False)
    monkeypatch.setattr(dr, "aws", fake)
    report = dr.audit()
    assert report["ready"] is False
    assert report["backup_plans"]["state"] == "UNOBSERVABLE"
    assert report["backup_vaults"]["state"] == "UNOBSERVABLE"
    assert all(row["state"] == "UNOBSERVABLE"
               for row in report["aws_backup_recovery_points"])
    assert report["storage"]["unencrypted_volume_ids"] == ["vol-allowed"]
    assert not any("create" in part or "start" in part for call in calls
                   for part in call)


def test_empty_authorized_inventory_is_missing_not_compliant(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-infra-scoped")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    fake, _ = _mock_aws(backup_visible=True)
    monkeypatch.setattr(dr, "aws", fake)
    report = dr.audit()
    assert report["backup_plans"]["state"] == "NONE"
    assert report["backup_vaults"]["state"] == "NONE"
    assert all(row["state"] == "NONE" for row in report["aws_backup_recovery_points"])
    assert report["storage"]["all_volumes_encrypted"] is False
    assert report["restore_verified"] is False


def test_even_recovery_points_and_encryption_do_not_fake_restore(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-infra-scoped")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    fake, _ = _mock_aws(backup_visible=True, encrypted=True, backup_present=True)
    monkeypatch.setattr(dr, "aws", fake)
    report = dr.audit()
    assert report["backup_plans"]["state"] == "PRESENT_SCOPE_NOT_VERIFIED"
    assert report["backup_vaults"]["state"] == "PRESENT"
    assert report["storage"]["all_volumes_encrypted"] is True
    assert all(row["state"] == "PRESENT" for row in report["aws_backup_recovery_points"])
    assert report["ready"] is False
    assert report["restore_verified"] is False
