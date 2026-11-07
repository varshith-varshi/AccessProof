#!/usr/bin/env python3
"""Fail-closed read-only prerequisites for a separately provisioned certifier.

Validates the actual EC2 identity, restricted assumed AWS role, and pinned
Ed25519 KMS public-key metadata. NEVER signs a message, renews a certificate,
imports evidence, copies employee sessions, or starts a signing service.

This tool can say the HOST is eligible for the next migration review, but it
can NEVER declare certification automation active.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import urllib.request
from datetime import datetime, timezone

REGION = "eu-north-1"
_ACCOUNT = r"[0-9]{12}"
KMS_ARN = re.compile(rf"^arn:aws:kms:{REGION}:{_ACCOUNT}:key/[0-9a-fA-F-]{{36}}$")
ROLE_ARN = re.compile(rf"^arn:aws:iam::{_ACCOUNT}:role/[A-Za-z0-9_+=,.@-]{{1,64}}$")
INSTANCE_ID = re.compile(r"^i-[0-9a-f]{17}$")


def imds_instance_id() -> str | None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        request = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            data=b"",
            method="PUT",
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


def aws_read_only(*args: str) -> dict | None:
    cmd = ["aws", *args, "--region", REGION, "--output", "json"]
    try:
        run = subprocess.run(cmd, capture_output=True, text=True, timeout=18, check=False)
        if run.returncode:
            return None
        result = json.loads(run.stdout)
        return result if isinstance(result, dict) else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def report(*, expected_instance: str, role_arn: str, key_arn: str) -> dict:
    # Never permit a string from a remote URL, default profile, instance on
    # production/staging, or a malformed resource name to become identity proof.
    args_ok = bool(
        INSTANCE_ID.fullmatch(expected_instance)
        and ROLE_ARN.fullmatch(role_arn)
        and KMS_ARN.fullmatch(key_arn)
        and role_arn.split(":")[4] == key_arn.split(":")[4]
    )
    no_static_credentials = not any(os.getenv(name) for name in (
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE",
    ))
    explicit_profile = os.getenv("AWS_PROFILE") == "accessproof-certifier"
    instance = imds_instance_id() if args_ok else None
    on_expected_host = bool(
        instance == expected_instance
        and instance not in {"i-0c11427d4d9c1b438", "i-0e6d2256a1e5a6f67"}
    )
    expected_assumed = (
        "arn:aws:sts::" + role_arn.split(":")[4]
        + ":assumed-role/" + role_arn.rsplit("/", 1)[1] + "/"
    )
    role = (
        aws_read_only("sts", "get-caller-identity")
        if args_ok and no_static_credentials and explicit_profile and on_expected_host
        else None
    )
    correct_aws_role = bool(role and str(role.get("Arn", "")).startswith(expected_assumed))
    public = (
        aws_read_only("kms", "get-public-key", "--key-id", key_arn,
                      "--query", "{KeyId:KeyId,KeySpec:KeySpec,KeyUsage:KeyUsage,SigningAlgorithms:SigningAlgorithms}")
        if correct_aws_role else None
    )
    correct_kms_public_key = bool(
        public and public.get("KeyId") == key_arn
        and public.get("KeySpec") == "ECC_NIST_EDWARDS25519"
        and public.get("KeyUsage") == "SIGN_VERIFY"
        and "ED25519_SHA_512" in public.get("SigningAlgorithms", [])
    )
    flags = {
        "resource_ids_valid": args_ok,
        "aws_profile_scoped": explicit_profile,
        "no_static_aws_credentials": no_static_credentials,
        "expected_isolated_ec2_host": on_expected_host,
        "assumed_restricted_certifier_role": correct_aws_role,
        "pinned_kms_public_key_supported": correct_kms_public_key,
    }
    return {
        "schema": "accessproof.independent_certifier_host_preflight/v1",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "host_prerequisites": "PASS" if all(flags.values()) else "BLOCKED",
        "checks": flags,
        "signing_enabled": False,
        "production_import_enabled": False,
        "trust_pin_verified": False,
        "employee_authorization_verified": False,
        "customer_route_independent": False,
        "migration_complete": False,
        "note": "Host prerequisites alone NEVER authorize certificate issuance or disable legacy renewal.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-instance-id", required=True)
    parser.add_argument("--expected-role-arn", required=True)
    parser.add_argument("--kms-key-arn", required=True)
    args = parser.parse_args()
    outcome = report(
        expected_instance=args.expected_instance_id,
        role_arn=args.expected_role_arn,
        key_arn=args.kms_key_arn,
    )
    print(json.dumps(outcome, sort_keys=True))
    return 0 if outcome["host_prerequisites"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
