#!/usr/bin/env bash
# AWS OWNER ONLY. Publish the reviewed release document and make it the default.
# The production deployer role is denied document changes by design, so this
# must run under the owner's own AWS session, never the deployer.
set -Eeuo pipefail
REGION=eu-north-1
NAME=AccessProof-Deployer-ProductionRelease
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILE="$HERE/ssm/$NAME.json"
# Validate generated URL allowance BEFORE invoking an AWS owner mutation.
# AWS SSM RE2 rejects counted regex repetitions above 1000; session-signed
# presigned S3 URLs are often >2000 base64 characters.
python3 - "$FILE" <<'PY_CHECK'
import base64, json, re, sys
from pathlib import Path
content = json.loads(Path(sys.argv[1]).read_text())
pattern = content["parameters"]["artifactUrlB64"]["allowedPattern"]
value = base64.b64encode(b"x" * 1708).decode("ascii")
assert len(value) == 2280 and re.fullmatch(pattern, value), "Document still rejects 2280-character signed URLs"
for low, high in re.findall(r"\{(\d+)(?:,(\d+))?\}", pattern):
    assert int(low) <= 1000 and (not high or int(high) <= 1000), "Unsupported SSM regex repetition count"
commands = content["mainSteps"][0]["inputs"]["runCommand"]
assert any("url_len=${#SSM_artifactUrlB64}" in command and '"$url_len" -le 4096' in command for command in commands)
print("Release document validation passed (signed URL length 2280, runtime limit 4096).")
PY_CHECK
ARN=$(env -u AWS_PROFILE aws sts get-caller-identity --query Arn --output text)
[[ "$ARN" != *accessproof-production-deployer* ]] || { echo 'Run this as the AWS owner, not the deployer' >&2; exit 2; }
echo "Publishing $NAME as $ARN"
VERSION=$(env -u AWS_PROFILE aws ssm update-document --region "$REGION" --name "$NAME" \
  --content "file://$FILE" --document-format JSON --document-version '$LATEST' \
  --query DocumentDescription.DocumentVersion --output text)
env -u AWS_PROFILE aws ssm update-document-default-version --region "$REGION" --name "$NAME" \
  --document-version "$VERSION" >/dev/null
echo "Default version of $NAME is now $VERSION"
