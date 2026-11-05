#!/usr/bin/env python3
"""Generate the tightly bounded AccessProof production deployer SSM documents.

No arbitrary shell inputs, command-string parameters, IAM privileges, or
customer secrets. Generated documents must be approved by the AWS owner.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ACCOUNT = '102076848988'
REGION = 'eu-north-1'
PROD = 'i-0c11427d4d9c1b438'
BUCKET = f'accessproof-release-artifacts-{ACCOUNT}-{REGION}'
DOCUMENT_RELEASE = 'AccessProof-Deployer-ProductionRelease'
DOCUMENT_PREFLIGHT = 'AccessProof-Deployer-ProductionPreflight'


def common() -> list[str]:
    return [
        'set -eu',
        'META=$(curl -fsS --max-time 2 -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")',
        'SELF=$(curl -fsS --max-time 2 -H "X-aws-ec2-metadata-token: $META" http://169.254.169.254/latest/meta-data/instance-id)',
        f'test "$SELF" = "{PROD}" || {{ echo "Wrong production instance; refusing" >&2; exit 2; }}',
    ]


def preflight() -> dict:
    return {
        'schemaVersion': '2.2',
        'description': 'Read-only preflight for AccessProof pinned production release; no input parameters.',
        'mainSteps': [{
            'action': 'aws:runShellScript',
            'name': 'preflight',
            'inputs': {'timeoutSeconds': '80', 'runCommand': common() + [
                'cd /home/ubuntu/accessproof',
                'echo "DB_REVISION=$(docker compose -f docker-compose.ec2.yml exec -T db psql -U accessproof -d accessproof -tAc \'select version_num from alembic_version\' | tr -d \'[:space:]\')"',
                'echo "DISK_FREE_GB=$(df -BG --output=avail / | tail -1 | tr -dc 0-9)"',
                'echo "SERVICES"',
                "docker compose -f docker-compose.ec2.yml ps --format '{{.Service}} {{.Status}}'",
                'echo "ZIP_SHA256=$(docker exec "$(docker compose -f docker-compose.ec2.yml ps -q web)" sha256sum /app/public/downloads/accessproof-gateway-connector.zip | cut -d\' \' -f1)"',
            ]},
        }],
    }


def release() -> dict:
    url_validation = (
        "python3 - \"$ZIP_URL\" <<'PYURL'\n"
        'import re, sys\n'
        'from urllib.parse import urlparse, parse_qs\n'
        'u = urlparse(sys.argv[1]); q = parse_qs(u.query)\n'
        f"assert u.scheme == 'https' and u.hostname == '{BUCKET}.s3.{REGION}.amazonaws.com', 'Invalid artifact host'\n"
        "assert not u.username and not u.password and not u.fragment and not u.port\n"
        "assert re.fullmatch(r'/releases/[a-z0-9][a-z0-9-]{5,80}-[0-9a-f]{12}\\.tar', u.path), 'Invalid object path'\n"
        "assert q.get('X-Amz-Algorithm') == ['AWS4-HMAC-SHA256'], 'Missing SigV4'\n"
        "assert q.get('X-Amz-Signature') and re.fullmatch('[0-9a-f]{64}', q['X-Amz-Signature'][0]), 'Missing signature'\n"
        "assert q.get('X-Amz-Expires') and int(q['X-Amz-Expires'][0]) <= 900, 'Excessive URL TTL'\n"
        'PYURL'
    )
    return {
        'schemaVersion': '2.2',
        'description': 'Release only one checksummed, pinned Git artifact to AccessProof production. No arbitrary command parameter.',
        'parameters': {
            'releaseId': {'type': 'String', 'interpolationType': 'ENV_VAR', 'allowedPattern': '^[a-z0-9][a-z0-9-]{5,80}$'},
            'commitSha': {'type': 'String', 'interpolationType': 'ENV_VAR', 'allowedPattern': '^[a-f0-9]{40}$'},
            'archiveSha256': {'type': 'String', 'interpolationType': 'ENV_VAR', 'allowedPattern': '^[a-f0-9]{64}$'},
            'expectedDbRevision': {'type': 'String', 'interpolationType': 'ENV_VAR', 'allowedPattern': '^[a-z0-9]{12}$'},
            'artifactUrlB64': {'type': 'String', 'interpolationType': 'ENV_VAR', 'allowedPattern': '^[A-Za-z0-9+/=]+$'},
        },
        'mainSteps': [{
            'action': 'aws:runShellScript',
            'name': 'deployPinnedRelease',
            'inputs': {'timeoutSeconds': '3600', 'runCommand': common() + [
                'test -n "${SSM_releaseId:-}" && test -n "${SSM_commitSha:-}" && test -n "${SSM_archiveSha256:-}" && test -n "${SSM_expectedDbRevision:-}" && test -n "${SSM_artifactUrlB64:-}" || { echo "SSM agent does not support ENV_VAR interpolation; refusing" >&2; exit 2; }',
                "REL=\"/home/ubuntu/accessproof-releases/$SSM_releaseId\"",
                'test ! -e "$REL" || { echo "Release ID already used" >&2; exit 2; }',
                'install -d -m 700 "$REL"',
                'url_len=${#SSM_artifactUrlB64}; test "$url_len" -ge 100 && test "$url_len" -le 4096 || { echo "Bad signed URL length" >&2; exit 2; }',
                "ZIP_URL=$(printf '%s' \"$SSM_artifactUrlB64\" | base64 -d)",
                url_validation,
                'curl --fail --silent --show-error --location --max-time 90 -o "$REL/artifact.tar" "$ZIP_URL"',
                "printf '%s  %s\\n' \"$SSM_archiveSha256\" \"$REL/artifact.tar\" | sha256sum -c -",
                "test \"$(tar -xOf \"$REL/artifact.tar\" RELEASE_COMMIT)\" = \"$SSM_commitSha\" || { echo 'Git commit mismatch' >&2; exit 2; }",
                'tar -xOf "$REL/artifact.tar" deploy/ec2-release/deploy_on_ec2.sh > "$REL/deploy_on_ec2.sh"',
                'chmod 700 "$REL/deploy_on_ec2.sh"',
                "EXPECTED_DB_REVISION=\"$SSM_expectedDbRevision\" PUBLIC_CHECKS=1 bash \"$REL/deploy_on_ec2.sh\" \"$SSM_releaseId\" \"$REL/artifact.tar\" \"$SSM_archiveSha256\"",
            ]},
        }],
    }


def role_policy() -> dict:
    prod_resource = f'arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{PROD}'
    docs = [f'arn:aws:ssm:{REGION}:{ACCOUNT}:document/{name}' for name in (DOCUMENT_RELEASE, DOCUMENT_PREFLIGHT)]
    return {'Version': '2012-10-17', 'Statement': [
        {'Sid': 'OnlyProductionReleaseAndPreflight', 'Effect': 'Allow', 'Action': ['ssm:SendCommand'], 'Resource': [prod_resource, *docs]},
        {'Sid': 'ReadCommandResultsOnlyInReleaseRegion', 'Effect': 'Allow', 'Action': ['ssm:GetCommandInvocation', 'ssm:ListCommands', 'ssm:DescribeInstanceInformation'], 'Resource': '*', 'Condition': {'StringEquals': {'aws:RequestedRegion': REGION}}},
        {'Sid': 'PublishReleaseArchivesOnly', 'Effect': 'Allow', 'Action': ['s3:PutObject', 's3:GetObject'], 'Resource': f'arn:aws:s3:::{BUCKET}/releases/*'},
        {'Sid': 'NeverUseAWSManagedShellDocument', 'Effect': 'Deny', 'Action': 'ssm:SendCommand', 'Resource': 'arn:aws:ssm:*::document/*'},
        {'Sid': 'NoInteractiveAccessOrAuthorityChanges', 'Effect': 'Deny', 'Action': [
            'iam:*', 'rolesanywhere:*', 'organizations:*', 'sts:AssumeRole',
            'ssm:StartSession', 'ssm:CreateDocument', 'ssm:UpdateDocument',
            'ssm:UpdateDocumentDefaultVersion', 'ssm:DeleteDocument', 'ssm:ModifyDocumentPermission',
            'ec2-instance-connect:*', 'ec2:RunInstances', 'ec2:TerminateInstances', 'ec2:ModifyInstanceAttribute',
            's3:DeleteObject', 's3:DeleteBucket', 's3:PutBucketPolicy', 's3:PutBucketPublicAccessBlock',
        ], 'Resource': '*'},
    ]}


def render() -> None:
    out = ROOT / 'ssm'; out.mkdir(parents=True, exist_ok=True)
    for name, contents in ((DOCUMENT_PREFLIGHT, preflight()), (DOCUMENT_RELEASE, release())):
        (out / f'{name}.json').write_text(json.dumps(contents, indent=2) + '\n')
    (ROOT / 'iam-policy-production-deployer.json').write_text(json.dumps(role_policy(), indent=2) + '\n')
    print('Generated pinned production SSM documents and least-privilege IAM policy.')


if __name__ == '__main__':
    render()
