#!/usr/bin/env python3
"""Production EC2 -> KMS-encrypted S3 PostgreSQL backup, no plaintext temp dump.

Deployment is NOT automatic. Requires a separately approved immutable bucket,
customer-data backup IAM role, host-local DB authentication and isolated restore.
A completed backup does not establish RPO/RTO or restore readiness.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import uuid
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REGION = "eu-north-1"
ACCOUNT = "102076848988"
PRODUCTION_INSTANCE = "i-0c11427d4d9c1b438"
ROLE_PREFIX = f"arn:aws:sts::{ACCOUNT}:assumed-role/AccessProofProductionBackupWriter/"
KMS_ARN = re.compile(rf"arn:aws:kms:{REGION}:{ACCOUNT}:key/[0-9a-fA-F-]{{36}}\Z")
BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{2,61}\Z")
DB_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_-]{0,62}\Z")
STATIC_KEYS = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
               "AWS_SECURITY_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE")


class BackupRefused(RuntimeError):
    pass


def imds_instance_id() -> str | None:
    """Read the host identity using IMDSv2, without accepting proxy redirects."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        request = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            data=b"", method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        )
        with opener.open(request, timeout=2) as response:
            token = response.read(300).decode("ascii")
        if not token or len(token) > 300:
            return None
        request = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/instance-id",
            headers={"X-aws-ec2-metadata-token": token},
        )
        with opener.open(request, timeout=2) as response:
            return response.read(100).decode("ascii")
    except (OSError, ValueError, UnicodeError):
        return None


def aws_json(args: list[str], *, timeout: int = 30) -> dict:
    try:
        result = subprocess.run(
            ["aws", *args, "--region", REGION, "--output", "json"],
            capture_output=True, text=True, check=False, timeout=timeout,
        )
        if result.returncode:
            raise BackupRefused("AWS_OPERATION_DENIED_OR_FAILED")
        payload = json.loads(result.stdout)
        if not isinstance(payload, dict):
            raise BackupRefused("AWS_RESPONSE_INVALID")
        return payload
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        raise BackupRefused("AWS_READ_FAILED") from exc


def verify_host_and_role() -> None:
    if (os.geteuid() == 0
            or os.environ.get("AWS_PROFILE") != "accessproof-backup-writer"
            or any(os.environ.get(x) for x in STATIC_KEYS)):
        raise BackupRefused("SCOPED_BACKUP_ROLE_PROFILE_REQUIRED")
    if imds_instance_id() != PRODUCTION_INSTANCE:
        raise BackupRefused("WRONG_EC2_INSTANCE")
    identity = aws_json(["sts", "get-caller-identity"])
    if (identity.get("Account") != ACCOUNT
            or not str(identity.get("Arn", "")).startswith(ROLE_PREFIX)):
        raise BackupRefused("DEDICATED_BACKUP_ROLE_REQUIRED")


def check_settings(*, bucket: str, key_arn: str, db_host: str,
                   pgpass: Path, database: str, user: str, port: int) -> None:
    if not BUCKET.fullmatch(bucket) or ".." in bucket or not KMS_ARN.fullmatch(key_arn):
        raise BackupRefused("ENCRYPTION_BUCKET_OR_KEY_BINDING_INVALID")
    try:
        ip = ipaddress.ip_address(db_host)
    except ValueError as exc:
        raise BackupRefused("DB_HOST_MUST_BE_PRIVATE_LITERAL_ADDRESS") from exc
    if not (ip.is_private or ip.is_loopback) or ip.is_unspecified or ip.is_multicast:
        raise BackupRefused("DB_HOST_MUST_BE_PRIVATE")
    if not DB_NAME.fullmatch(database) or not DB_NAME.fullmatch(user):
        raise BackupRefused("DATABASE_OR_USERNAME_INVALID")
    if not 1 <= port <= 65535:
        raise BackupRefused("DATABASE_PORT_INVALID")
    try:
        info = pgpass.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.geteuid() or info.st_size < 1):
            raise BackupRefused("PRIVATE_PGPASSFILE_REQUIRED")
    except OSError as exc:
        raise BackupRefused("PRIVATE_PGPASSFILE_REQUIRED") from exc
    if os.environ.get("PGPASSWORD"):
        raise BackupRefused("PGPASSWORD_ENVIRONMENT_NOT_PERMITTED")


def pg_command(*, db_host: str, port: int, database: str, user: str) -> list[str]:
    return ["pg_dump", "--format=custom", "--no-owner", "--no-privileges",
            "--host", db_host, "--port", str(port), "--username", user, database]


def upload_args(bucket: str, key: str, kms_key: str) -> list[str]:
    return [
        "aws", "s3", "cp", "-", f"s3://{bucket}/{key}",
        "--sse", "aws:kms", "--sse-kms-key-id", kms_key,
        "--region", REGION, "--only-show-errors",
    ]


def verify_object(bucket: str, key: str, kms_arn: str, length: int) -> None:
    head = aws_json(["s3api", "head-object", "--bucket", bucket, "--key", key])
    if (head.get("ServerSideEncryption") != "aws:kms"
            or head.get("SSEKMSKeyId") != kms_arn
            or head.get("ContentLength") != length):
        raise BackupRefused("ENCRYPTED_S3_OBJECT_VERIFICATION_FAILED")


def perform(*, bucket: str, key_arn: str, db_host: str, port: int,
            database: str, user: str, pgpass: Path) -> dict:
    verify_host_and_role()
    check_settings(bucket=bucket, key_arn=key_arn, db_host=db_host,
                   pgpass=pgpass, database=database, user=user, port=port)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"database/{timestamp}-{uuid.uuid4().hex}"
    archive_key = f"{stem}.dump"
    manifest_key = f"{stem}.manifest.json"
    env = dict(os.environ)
    env["PGPASSFILE"] = str(pgpass)
    # Only data bytes cross the pipe. No unencrypted dump is written to disk.
    try:
        dump = subprocess.Popen(pg_command(db_host=db_host, port=port, database=database, user=user),
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    except OSError as exc:
        raise BackupRefused("DATABASE_DUMP_START_FAILED") from exc
    try:
        upload = subprocess.Popen(upload_args(bucket, archive_key, key_arn),
                                  stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
    except OSError as exc:
        # An AWS CLI startup failure must not orphan an active database dump.
        dump.terminate()
        if dump.stdout is not None:
            dump.stdout.close()
        try:
            dump.wait(timeout=10)
        except subprocess.TimeoutExpired:
            dump.kill()
            dump.wait(timeout=10)
        raise BackupRefused("S3_UPLOAD_START_FAILED") from exc
    digest = hashlib.sha256()
    count = 0
    stream_error = False
    try:
        assert dump.stdout is not None and upload.stdin is not None
        magic = b""
        while True:
            part = dump.stdout.read(1024 * 1024)
            if not part:
                break
            if len(magic) < 5:
                magic = (magic + part)[:5]
            digest.update(part)
            count += len(part)
            upload.stdin.write(part)
        upload.stdin.close()
        dump.stdout.close()
    except (BrokenPipeError, OSError):
        stream_error = True
        dump.terminate()
        try:
            upload.stdin.close() if upload.stdin else None
        except OSError:
            pass
    try:
        dump_rc = dump.wait(timeout=180)
        upload_rc = upload.wait(timeout=180)
    except subprocess.TimeoutExpired as exc:
        # If one side stalls after a partial stream, do not orphan children or
        # publish a commit marker for an incomplete archive.
        for process in (dump, upload):
            process.kill()
        for process in (dump, upload):
            process.wait(timeout=15)
        raise BackupRefused("BACKUP_PROCESS_TIMEOUT_NO_COMMIT_MANIFEST") from exc
    if stream_error or dump_rc or upload_rc or count < 5 or magic != b"PGDMP":
        # The uncommitted archive key is never trusted as a recovery point:
        # the manifest is intentionally absent on any incomplete upload.
        raise BackupRefused("BACKUP_STREAM_FAILED_NO_COMMIT_MANIFEST")
    verify_object(bucket, archive_key, key_arn, count)
    manifest = {
        "schema": "accessproof.production_postgres_backup/v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "instance_id": PRODUCTION_INSTANCE,
        "database": database,
        "object_key": archive_key,
        "bucket": bucket,
        "archive_sha256": digest.hexdigest(),
        "archive_bytes": count,
        "s3_kms_key_arn": key_arn,
        "restore_verified": False,
    }
    # Commit marker only after both pg_dump and the encrypted upload succeed.
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    marker = subprocess.run(upload_args(bucket, manifest_key, key_arn), input=encoded,
                            capture_output=True, check=False, timeout=90)
    if marker.returncode:
        raise BackupRefused("BACKUP_MANIFEST_UPLOAD_FAILED")
    verify_object(bucket, manifest_key, key_arn, len(encoded))
    # Never print connection secrets, source contents, or PGPASSFILE.
    return {"state": "ENCRYPTED_ARCHIVE_COMMITTED_RESTORE_UNVERIFIED",
            "bucket": bucket, "archive_key": archive_key, "manifest_key": manifest_key,
            "archive_bytes": count, "archive_sha256": digest.hexdigest(),
            "restore_verified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--kms-key-arn", required=True)
    parser.add_argument("--db-host", required=True)
    parser.add_argument("--db-port", type=int, default=5432)
    parser.add_argument("--database", required=True)
    parser.add_argument("--db-user", required=True)
    parser.add_argument("--pgpass-file", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = perform(bucket=args.bucket, key_arn=args.kms_key_arn,
                         db_host=args.db_host, port=args.db_port,
                         database=args.database, user=args.db_user,
                         pgpass=args.pgpass_file)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (BackupRefused, subprocess.TimeoutExpired) as exc:
        # A log may be consumed by operator monitoring: fail closed with a
        # fixed, non-sensitive reason.
        reason = str(exc) if isinstance(exc, BackupRefused) else "BACKUP_TIMEOUT"
        print(json.dumps({"state": "BACKUP_NOT_COMMITTED", "reason": reason,
                          "restore_verified": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
