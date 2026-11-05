#!/usr/bin/env bash
# AWS OWNER ONLY. Publish the reviewed release document and make it the default.
# The production deployer role is denied document changes by design, so this
# must run under the owner's own AWS session, never the deployer.
set -Eeuo pipefail
REGION=eu-north-1
NAME=AccessProof-Deployer-ProductionRelease
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILE="$HERE/ssm/$NAME.json"
ARN=$(env -u AWS_PROFILE aws sts get-caller-identity --query Arn --output text)
[[ "$ARN" != *accessproof-production-deployer* ]] || { echo 'Run this as the AWS owner, not the deployer' >&2; exit 2; }
echo "Publishing $NAME as $ARN"
VERSION=$(env -u AWS_PROFILE aws ssm update-document --region "$REGION" --name "$NAME" \
  --content "file://$FILE" --document-format JSON --document-version '$LATEST' \
  --query DocumentDescription.DocumentVersion --output text)
env -u AWS_PROFILE aws ssm update-document-default-version --region "$REGION" --name "$NAME" \
  --document-version "$VERSION" >/dev/null
echo "Default version of $NAME is now $VERSION"
