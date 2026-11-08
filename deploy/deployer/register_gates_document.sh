#!/usr/bin/env bash
# AWS OWNER ONLY (one time). Create the read-only production gates document and
# attach the regenerated deployer policy, so the deployer can run gates A-J with
#   deploy/deployer/ship_production.sh --gates <organization-id> <application-id>
# The deployer role is denied document and IAM changes by design; run this under
# the owner's own non-root administrator session (never the account root, never the deployer).
set -Eeuo pipefail
REGION=eu-north-1
NAME=AccessProof-Deployer-ProductionGates
ROLE=accessproof-production-deployer
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$HERE/build_ssm_documents.py"
ARN=$(env -u AWS_PROFILE aws sts get-caller-identity --query Arn --output text)
[[ "$ARN" != *"$ROLE"* ]] || { echo 'Run this as the AWS owner, not the deployer' >&2; exit 2; }
[[ "$ARN" != *":root" ]] || { echo 'Refusing to use the account root; use a non-root administrator' >&2; exit 2; }
echo "Creating/updating $NAME as $ARN"
if env -u AWS_PROFILE aws ssm describe-document --region "$REGION" --name "$NAME" >/dev/null 2>&1; then
  V=$(env -u AWS_PROFILE aws ssm update-document --region "$REGION" --name "$NAME" --content "file://$HERE/ssm/$NAME.json" \
      --document-format JSON --document-version '$LATEST' --query DocumentDescription.DocumentVersion --output text)
  env -u AWS_PROFILE aws ssm update-document-default-version --region "$REGION" --name "$NAME" --document-version "$V" >/dev/null
else
  env -u AWS_PROFILE aws ssm create-document --region "$REGION" --name "$NAME" --document-type Command \
    --content "file://$HERE/ssm/$NAME.json" --document-format JSON >/dev/null
fi
POLICY=$(env -u AWS_PROFILE aws iam list-role-policies --role-name "$ROLE" --query 'PolicyNames[0]' --output text)
[[ -n "$POLICY" && "$POLICY" != None ]] || { echo "No inline policy on $ROLE; attach iam-policy-production-deployer.json manually" >&2; exit 2; }
env -u AWS_PROFILE aws iam put-role-policy --role-name "$ROLE" --policy-name "$POLICY" \
  --policy-document "file://$HERE/iam-policy-production-deployer.json"
echo "Done: $ROLE may now run $NAME (read-only gates A-J)."
