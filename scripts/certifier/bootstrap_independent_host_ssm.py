#!/usr/bin/env python3
"""Deploy ONLY the read-only certifier host prerequisite timer via scoped SSM.

Runs on the owner's development workstation using the narrowly scoped
NON-ROOT AccessProof infrastructure role and the stack's verified outputs. Transmits only two
reviewed PUBLIC code files, never keys/tokens/employee sessions. Fails closed.
"""
from __future__ import annotations
import base64
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STACK = "accessproof-independent-certifier-2026"
REGION = "eu-north-1"
PROFILE = "accessproof-infra-scoped"
OPERATOR_ARN_PREFIX = "arn:aws:sts::102076848988:assumed-role/AccessProofIndependentInfraBootstrap/"
PROFILE_SRC = ROOT / "scripts/certifier/independent_host_preflight.py"
INSTALLER_SRC = ROOT / "deploy/certifier/independent/bootstrap_readonly_host.sh"


def aws(*args: str) -> dict:
    env = os.environ.copy()
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE"):
        if env.get(key):
            raise RuntimeError("ENVIRONMENT_CREDENTIAL_OVERRIDE_REFUSED")
    env["AWS_PROFILE"] = PROFILE
    p = subprocess.run(["aws", *args, "--region", REGION, "--output", "json"],
                       capture_output=True, text=True, check=False, timeout=40, env=env)
    if p.returncode:
        raise RuntimeError("AWS_READ_OR_WRITE_FAILED: " + p.stderr[:450])
    return json.loads(p.stdout)


def verify_target() -> tuple[str,str,str]:
    caller = aws("sts","get-caller-identity")
    if not str(caller.get("Arn", "")).startswith(OPERATOR_ARN_PREFIX):
        raise RuntimeError("AUTHENTICATED_SCOPED_CERTIFIER_OPERATOR_REQUIRED")
    s = aws("cloudformation","describe-stacks","--stack-name",STACK)["Stacks"][0]
    if s["StackStatus"] not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
        raise RuntimeError("INDEPENDENT_STACK_NOT_COMPLETE")
    outputs = {v["OutputKey"]:v["OutputValue"] for v in s.get("Outputs",[])}
    instance = outputs.get("CertifierInstanceId","")
    role = outputs.get("CertifierExecutionRoleArn","")
    key = outputs.get("CertifierSigningKeyArn","")
    subnet = outputs.get("CertifierPrivateSubnetId","")
    if not re.fullmatch("i-[0-9a-f]{17}",instance):
        raise RuntimeError("MISSING_PINNED_INSTANCE")
    if role != "arn:aws:iam::102076848988:role/AccessProofIndependentCertifierExec2026":
        raise RuntimeError("WRONG_CERTIFIER_ROLE")
    if not re.fullmatch(r"arn:aws:kms:eu-north-1:102076848988:key/[0-9a-fA-F-]{36}",key):
        raise RuntimeError("WRONG_KMS_KEY_ARN")
    e = aws("ec2","describe-instances","--instance-ids",instance)["Reservations"][0]["Instances"][0]
    if (e["State"]["Name"] != "running"
            or e.get("PublicIpAddress")
            or e.get("SubnetId") != subnet
            or e.get("VpcId") != "vpc-0be4dc69e57c09b2f"):
        raise RuntimeError("HOST_TOPOLOGY_NOT_APPROVED")
    statuses = aws("ssm","describe-instance-information","--filters","Key=InstanceIds,Values="+instance).get("InstanceInformationList",[])
    if not any(x.get("InstanceId")==instance and x.get("PingStatus")=="Online" for x in statuses):
        raise RuntimeError("SSM_AGENT_NOT_YET_ONLINE")
    return instance,role,key


def encoded(path: Path) -> tuple[str,str]:
    data = path.read_bytes()
    return base64.b64encode(gzip.compress(data,mtime=0)).decode("ascii"), hashlib.sha256(data).hexdigest()


def make_commands(instance: str, role: str, key: str) -> list[str]:
    src, src_sha = encoded(PROFILE_SRC)
    install, install_sha = encoded(INSTALLER_SRC)
    commands = [
        "set -euo pipefail",
        "mkdir -p /opt/accessproof-independent-certifier-src/scripts/certifier /opt/accessproof-independent-certifier-src/deploy/certifier/independent",
        "printf '%s' '"+src+"' | base64 -d | gzip -d > /opt/accessproof-independent-certifier-src/scripts/certifier/independent_host_preflight.py",
        "printf '%s' '"+install+"' | base64 -d | gzip -d > /opt/accessproof-independent-certifier-src/deploy/certifier/independent/bootstrap_readonly_host.sh",
        "echo '"+src_sha+"  /opt/accessproof-independent-certifier-src/scripts/certifier/independent_host_preflight.py' | sha256sum -c",
        "echo '"+install_sha+"  /opt/accessproof-independent-certifier-src/deploy/certifier/independent/bootstrap_readonly_host.sh' | sha256sum -c",
        "cd /opt/accessproof-independent-certifier-src",
        "bash deploy/certifier/independent/bootstrap_readonly_host.sh "+instance+" "+role+" "+key,
        "systemctl start accessproof-independent-certifier-preflight.service || true",
        "systemctl show accessproof-independent-certifier-preflight.service -p Result -p ExecMainStatus",
        "journalctl -u accessproof-independent-certifier-preflight.service -n 10 --no-pager --output=cat",
    ]
    if any(len(x)>3900 for x in commands):
        raise RuntimeError("SSM_COMMAND_LENGTH_LIMIT")
    return commands


def main() -> int:
    instance,role,key = verify_target()
    params={"commands":make_commands(instance,role,key),"executionTimeout":["180"]}
    tmp = tempfile.NamedTemporaryFile("w",prefix="accessproof-ssm-readonly-",suffix=".json",delete=False)
    try:
        os.fchmod(tmp.fileno(),0o600)
        json.dump(params,tmp)
        tmp.close()
        sent=aws("ssm","send-command","--document-name","AWS-RunShellScript",
                 "--instance-ids",instance,"--parameters","file://"+tmp.name,
                 "--comment","Install read-only certifier EC2 identity/KMS preflight (no signing)")
    finally:
        tmp.close()
        Path(tmp.name).unlink(missing_ok=True)
    print(json.dumps({"command_id":sent["Command"]["CommandId"],
                      "instance":instance,"operation":"READ_ONLY_HOST_BOOTSTRAP",
                      "certificate_signing_enabled":False,"source_renewal_migrated":False},
                     sort_keys=True))
    return 0


if __name__=="__main__":
    try: sys.exit(main())
    except (RuntimeError,ValueError,KeyError,IndexError) as exc:
        print("BOOTSTRAP_BLOCKED: "+str(exc),file=sys.stderr)
        sys.exit(2)
