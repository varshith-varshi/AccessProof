#!/usr/bin/env python3
"""Read-only authorization and networking preflight; never deploy as root.

Usage:
  AWS_PROFILE=<nonroot-infrastructure-admin> python3 scripts/certifier/independent_deployment_preflight.py

Reports precise pending IAM/network readiness without changing AWS resources.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

REGION = "eu-north-1"
TARGET = "accessproof-independent-certifier-2026"
VPC = "vpc-0be4dc69e57c09b2f"
SUBNET = "subnet-0152c2e25be9200e3"
CIDR = "172.31.48.0/24"
ZONE = "eu-north-1c"
TEMPLATE = Path(__file__).resolve().parents[2] / "deploy/certifier/independent/isolated-certifier-stack.json"


def cli(*args: str) -> tuple[bool, object]:
    try:
        run = subprocess.run(
            ["aws", *args, "--region", REGION, "--output", "json"],
            capture_output=True, text=True, check=False, timeout=25
        )
        if run.returncode:
            return False, ("ACCESS_DENIED" if "AccessDenied" in run.stderr
                           or "not authorized" in run.stderr else "AWS_CALL_FAILED")
        return True, json.loads(run.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return False, "AWS_CALL_FAILED"


def preflight() -> dict:
    checks = {}
    profile = os.environ.get("AWS_PROFILE", "")
    checks["explicit_named_profile"] = bool(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,80}", profile)
        and profile not in {"default", "root"}
    )
    checks["no_static_session_override"] = not any(
        os.environ.get(k) for k in (
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
            "AWS_SECURITY_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE"
        )
    )
    template = json.loads(TEMPLATE.read_text())
    checks["reviewed_template_has_private_instance"] = (
        template["Resources"]["CertifierInstance"]["Properties"][
            "NetworkInterfaces"][0]["AssociatePublicIpAddress"] is False
        and template["Resources"]["CertifierPrivateSubnet"]["Properties"][
            "MapPublicIpOnLaunch"] is False
    )
    if not all(checks.values()):
        return {"ready": False, "checks": checks,
                "blocker": "EXPLICIT_NONROOT_AWS_PROFILE_REQUIRED",
                "deployed": False}
    identity_ok, who = cli("sts", "get-caller-identity")
    arn = str(who.get("Arn", "")) if identity_ok and isinstance(who, dict) else ""
    checks["nonroot_identity"] = bool(
        arn and not arn.endswith(":root") and (
            ":assumed-role/" in arn or ":user/" in arn
        )
    )
    if not checks["nonroot_identity"]:
        return {"ready": False, "checks": checks,
                "blocker": "NONROOT_IDENTITY_REQUIRED", "deployed": False}
    valid, _ = cli("cloudformation", "validate-template", "--template-body",
                   f"file://{TEMPLATE}")
    checks["cloudformation_validate_authorized"] = valid
    subnet_ok, subnets = cli("ec2", "describe-subnets", "--subnet-ids", SUBNET)
    checks["public_subnet_matches_review"] = bool(
        subnet_ok and isinstance(subnets, dict)
        and len(subnets.get("Subnets", [])) == 1
        and subnets["Subnets"][0].get("VpcId") == VPC
        and subnets["Subnets"][0].get("AvailabilityZone") == ZONE
    )
    existing_ok, stacks = cli("cloudformation", "list-stacks")
    checks["stack_inspection_authorized"] = existing_ok
    same = [
        s for s in stacks.get("StackSummaries", [])
        if s.get("StackName") == TARGET and not s.get("StackStatus", "").startswith("DELETE")
    ] if existing_ok and isinstance(stacks, dict) else []
    checks["no_conflicting_active_stack"] = existing_ok and not same
    # A deployed, reviewed stack is not a missing deployment. Verify its
    # identity and outputs, and NEVER print a second creation command.
    # This preflight cannot authorize signing, renewal, or credential custody.
    if same:
        if len(same) != 1:
            return {"ready": False, "deployed": False, "checks": checks,
                    "blocker": "DUPLICATE_CERTIFIER_STACK_SUMMARIES"}
        inspected, response = cli("cloudformation", "describe-stacks", "--stack-name", TARGET)
        records = response.get("Stacks", []) if inspected and isinstance(response, dict) else []
        verified = len(records) == 1 and records[0].get("StackName") == TARGET
        stack = records[0] if verified else {}
        status = stack.get("StackStatus", "")
        expected = {"CertifierInstanceId", "CertifierExecutionRoleArn", "CertifierSigningKeyArn"}
        outputs = {o.get("OutputKey") for o in stack.get("Outputs", [])
                   if isinstance(o, dict) and o.get("OutputValue")}
        deployed = status in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "IMPORT_COMPLETE"} \
            and expected.issubset(outputs)
        checks["existing_stack_verified"] = deployed
        return {
            "ready": False,
            "deployed": deployed,
            "existing_stack_status": status if isinstance(status, str) else "",
            "checks": checks,
            "blocker": ("EXISTING_CERTIFIER_STACK_REQUIRES_APPROVED_SIGNING_CUTOVER"
                        if deployed else "EXISTING_CERTIFIER_STACK_REQUIRES_REVIEW"),
            "template": str(TEMPLATE),
            "signing_enabled": False,
            "renewal_independent": False,
        }
    # Server-side StackSets/CloudFormation deploy authorizations can differ
    # from validation; success does NOT prove the role can deploy.
    checks["deployment_permissions_separately_required"] = False
    return {
        "ready": False, "checks": checks, "deployed": False,
        "blocker": "DEPLOYMENT_REQUIRES_SCOPED_INFRASTRUCTURE_ADMIN_REVIEW"
                   if all(v for k,v in checks.items() if k != "deployment_permissions_separately_required")
                   else "PREFLIGHT_CHECKS_FAILED",
        "template": str(TEMPLATE),
        "command_for_authorized_admin": (
            "aws cloudformation deploy --region eu-north-1 "
            "--stack-name accessproof-independent-certifier-2026 "
            f"--template-file {TEMPLATE} --capabilities CAPABILITY_IAM "
            f"--parameter-overrides VpcId={VPC} PublicSubnetId={SUBNET} "
            f"PrivateSubnetCidr={CIDR} CertifierAvailabilityZone={ZONE}"
        ),
    }


if __name__ == "__main__":
    print(json.dumps(preflight(), sort_keys=True))
    sys.exit(2)
