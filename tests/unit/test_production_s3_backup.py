"""Fail-closed, no-plaintext, KMS-bound production backup unit tests."""
from __future__ import annotations

import io
import subprocess

import pytest

from scripts.drills import production_s3_backup as b


KMS = f"arn:aws:kms:{b.REGION}:{b.ACCOUNT}:key/12345678-abcd-1234-abcd-1234567890ab"


def test_only_production_host_and_scoped_role_accepted(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-backup-writer")
    for name in b.STATIC_KEYS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(b.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(b, "imds_instance_id", lambda: b.PRODUCTION_INSTANCE)
    monkeypatch.setattr(b, "aws_json", lambda _: {
        "Account": b.ACCOUNT, "Arn": b.ROLE_PREFIX + "new-session",
    })
    b.verify_host_and_role()
    monkeypatch.setenv("AWS_PROFILE", "accessproof-production-deployer")
    with pytest.raises(b.BackupRefused, match="SCOPED"):
        b.verify_host_and_role()
    monkeypatch.setenv("AWS_PROFILE", "accessproof-backup-writer")
    monkeypatch.setattr(b, "imds_instance_id", lambda: "i-0other")
    with pytest.raises(b.BackupRefused, match="WRONG_EC2"):
        b.verify_host_and_role()


def test_backup_refuses_static_credentials_and_root(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "accessproof-backup-writer")
    monkeypatch.setattr(b.os, "geteuid", lambda: 1000)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fake")
    with pytest.raises(b.BackupRefused, match="SCOPED"):
        b.verify_host_and_role()
    monkeypatch.delenv("AWS_ACCESS_KEY_ID")
    monkeypatch.setattr(b.os, "geteuid", lambda: 0)
    with pytest.raises(b.BackupRefused, match="SCOPED"):
        b.verify_host_and_role()


@pytest.mark.parametrize("host", ["8.8.8.8", "db.example.com", "0.0.0.0"])
def test_private_database_required(tmp_path, monkeypatch, host):
    pgpass = tmp_path / "pgpass"
    pgpass.write_text("test-credentials")
    pgpass.chmod(0o600)
    monkeypatch.setattr(b.os, "geteuid", lambda: pgpass.stat().st_uid)
    with pytest.raises(b.BackupRefused, match="DB_HOST"):
        b.check_settings(bucket="accessproof-prod-backups", key_arn=KMS,
                         db_host=host, pgpass=pgpass, database="accessproof",
                         user="backup_reader", port=5432)


def test_pgpass_must_be_private_regular_file(tmp_path, monkeypatch):
    pgpass = tmp_path / "pgpass"
    pgpass.write_text("fixture")
    pgpass.chmod(0o644)
    monkeypatch.setattr(b.os, "geteuid", lambda: pgpass.stat().st_uid)
    with pytest.raises(b.BackupRefused, match="PRIVATE_PGPASSFILE"):
        b.check_settings(bucket="accessproof-prod-backups", key_arn=KMS,
                         db_host="127.0.0.1", pgpass=pgpass, database="accessproof",
                         user="backup_reader", port=5432)
    pgpass.chmod(0o600)
    b.check_settings(bucket="accessproof-prod-backups", key_arn=KMS,
                     db_host="127.0.0.1", pgpass=pgpass, database="accessproof",
                     user="backup_reader", port=5432)
    symlink = tmp_path / "linked"
    symlink.symlink_to(pgpass)
    with pytest.raises(b.BackupRefused, match="PRIVATE_PGPASSFILE"):
        b.check_settings(bucket="accessproof-prod-backups", key_arn=KMS,
                         db_host="127.0.0.1", pgpass=symlink, database="accessproof",
                         user="backup_reader", port=5432)


def test_strict_object_encryption_is_required(monkeypatch):
    monkeypatch.setattr(b, "aws_json", lambda *args: {
        "ServerSideEncryption": "AES256", "ContentLength": 20,
        "SSEKMSKeyId": KMS,
    })
    with pytest.raises(b.BackupRefused, match="ENCRYPTED"):
        b.verify_object("accessproof-prod-backups", "safe", KMS, 20)


def test_only_signed_off_manifest_marks_backup_committed(monkeypatch, tmp_path):
    class FakeDump:
        def __init__(self, rc):
            self.stdout = io.BytesIO(b"PGDMPtest-content")
            self.returncode = rc
        def wait(self, timeout):
            return self.returncode
        def terminate(self):
            pass

    class FakeS3:
        def __init__(self, rc):
            self.stdin = io.BytesIO()
            self.returncode = rc
        def wait(self, timeout):
            return self.returncode

    commands = []
    def fake_popen(argv, **kwargs):
        commands.append(argv)
        return FakeDump(0) if argv[0] == "pg_dump" else FakeS3(0)

    reports = []
    monkeypatch.setattr(b, "verify_host_and_role", lambda: None)
    monkeypatch.setattr(b, "check_settings", lambda **kwargs: None)
    monkeypatch.setattr(b.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(b, "verify_object", lambda *args: reports.append(args))
    def marker(argv, **kwargs):
        assert b'"restore_verified":false' in kwargs["input"]
        return subprocess.CompletedProcess(argv, 0)
    monkeypatch.setattr(b.subprocess, "run", marker)

    value = b.perform(bucket="accessproof-prod-backups", key_arn=KMS,
                      db_host="127.0.0.1", port=5432, database="accessproof",
                      user="backup_reader", pgpass=tmp_path / "unread")
    assert value["restore_verified"] is False
    assert value["archive_bytes"] == len(b"PGDMPtest-content")
    assert value["state"] == "ENCRYPTED_ARCHIVE_COMMITTED_RESTORE_UNVERIFIED"
    assert len(reports) == 2
    assert commands[0][0] == "pg_dump"
    assert commands[1][0:3] == ["aws", "s3", "cp"]


@pytest.mark.parametrize("dump_rc, upload_rc, content", [
    (1, 0, b"PGDMPtest"), (0, 1, b"PGDMPtest"), (0, 0, b"not-a-dump")
])
def test_failed_or_invalid_dump_never_creates_manifest(
    monkeypatch, tmp_path, dump_rc, upload_rc, content,
):
    class FakeDump:
        stdout = io.BytesIO(content)
        def wait(self, timeout):
            return dump_rc
        def terminate(self):
            pass
    class FakeUpload:
        stdin = io.BytesIO()
        def wait(self, timeout):
            return upload_rc
    def popen(argv, **kwargs):
        return FakeDump() if argv[0] == "pg_dump" else FakeUpload()
    monkeypatch.setattr(b, "verify_host_and_role", lambda: None)
    monkeypatch.setattr(b, "check_settings", lambda **kwargs: None)
    monkeypatch.setattr(b.subprocess, "Popen", popen)
    monkeypatch.setattr(b, "verify_object", lambda *a: None)
    monkeypatch.setattr(b.subprocess, "run", lambda *a, **kw: (_ for _ in ()).throw(
        AssertionError("MUST NOT UPLOAD MANIFEST")))
    with pytest.raises(b.BackupRefused, match="NO_COMMIT_MANIFEST"):
        b.perform(bucket="accessproof-prod-backups", key_arn=KMS,
                  db_host="127.0.0.1", port=5432, database="accessproof",
                  user="backup_reader", pgpass=tmp_path / "unread")


def test_upload_start_failure_kills_database_dump(monkeypatch, tmp_path):
    class Dump:
        def __init__(self):
            self.stdout = io.BytesIO(b"unused")
            self.terminated = False
            self.waited = False
        def terminate(self):
            self.terminated = True
        def wait(self, timeout):
            self.waited = True
            return 1
    dump = Dump()
    def fake_start(argv, **kwargs):
        if argv[0] == "pg_dump":
            return dump
        raise OSError("AWS CLI unavailable")
    monkeypatch.setattr(b, "verify_host_and_role", lambda: None)
    monkeypatch.setattr(b, "check_settings", lambda **kwargs: None)
    monkeypatch.setattr(b.subprocess, "Popen", fake_start)
    with pytest.raises(b.BackupRefused, match="S3_UPLOAD_START_FAILED"):
        b.perform(bucket="accessproof-prod-backups", key_arn=KMS,
                  db_host="127.0.0.1", port=5432, database="accessproof",
                  user="backup_reader", pgpass=tmp_path / "unread")
    assert dump.terminated is True
    assert dump.waited is True
    assert dump.stdout.closed is True


def test_stream_timeout_kills_both_processes_and_never_commits(monkeypatch, tmp_path):
    class StreamDump:
        def __init__(self):
            self.stdout = io.BytesIO(b"PGDMPtest")
            self.killed = False
            self.waited = False
        def wait(self, timeout):
            if not self.killed:
                raise subprocess.TimeoutExpired("pg_dump", timeout)
            self.waited = True
            return -9
        def kill(self):
            self.killed = True
    class StreamS3:
        def __init__(self):
            self.stdin = io.BytesIO()
            self.killed = False
            self.waited = False
        def wait(self, timeout):
            self.waited = True
            return -9
        def kill(self):
            self.killed = True
    dump = StreamDump()
    upload = StreamS3()
    def popen(argv, **kwargs):
        return dump if argv[0] == "pg_dump" else upload
    monkeypatch.setattr(b, "verify_host_and_role", lambda: None)
    monkeypatch.setattr(b, "check_settings", lambda **kwargs: None)
    monkeypatch.setattr(b.subprocess, "Popen", popen)
    monkeypatch.setattr(b.subprocess, "run", lambda *a, **kw: (_ for _ in ()).throw(
        AssertionError("incomplete archive cannot be committed")))
    with pytest.raises(b.BackupRefused, match="TIMEOUT_NO_COMMIT_MANIFEST"):
        b.perform(bucket="accessproof-prod-backups", key_arn=KMS,
                  db_host="127.0.0.1", port=5432, database="accessproof",
                  user="backup_reader", pgpass=tmp_path / "unread")
    assert dump.killed and upload.killed
    assert dump.waited and upload.waited
