#!/usr/bin/env bash
# Operator workstation: ship a git-committed AccessProof release to EC2 via
# private S3 + AWS Systems Manager, then run deploy_on_ec2.sh there.
#
#   bash deploy/ec2-release/ship_via_ssm.sh <git-commit>
#
# Requires valid AWS credentials for account 102076848988. Makes NO IAM,
# security-group or instance changes: the instance downloads the artifact
# with a 15-minute presigned URL. The temporary bucket blocks public access,
# uses SSE-S3, and is deleted at the end.
set -Eeuo pipefail
umask 077
COMMIT=$(git rev-parse --verify "${1:?git commit}^{commit}")
ACCOUNT=102076848988; REGION=eu-north-1; INSTANCE=i-0c11427d4d9c1b438
RELEASE_ID="r20-cert-presence-${COMMIT:0:12}"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

[[ "$(aws sts get-caller-identity --query Account --output text)" == "$ACCOUNT" ]] \
  || { echo "wrong AWS account"; exit 2; }
[[ -z "$(git status --porcelain)" ]] || echo "note: working tree dirty; shipping committed $COMMIT only"
aws ssm describe-instance-information --region "$REGION" \
  --filters "Key=InstanceIds,Values=$INSTANCE" --query 'InstanceInformationList[0].PingStatus' --output text \
  | grep -qx Online || { echo "instance not SSM-online"; exit 2; }

ART="$WORK/accessproof-$RELEASE_ID.tar"
git archive --format=tar --add-virtual-file=RELEASE_COMMIT:"$COMMIT" -o "$ART" "$COMMIT"
# Refuse to ship secrets or bulky archives.
if tar -tf "$ART" | grep -Eiq '(^|/)\.env$|\.pem$|\.key$|\.dump$|\.zip$|credentials\.json$'; then
  echo "artifact contains a forbidden file type"; exit 2
fi
SHA=$(sha256sum "$ART" | cut -d' ' -f1)
echo "release=$RELEASE_ID sha256=$SHA"

BUCKET="accessproof-release-transfer-$(date -u +%Y%m%d%H%M%S)-$RANDOM"
cleanup_bucket() {
  aws s3 rm "s3://$BUCKET" --recursive --region "$REGION" >/dev/null 2>&1 || true
  aws s3api delete-bucket --bucket "$BUCKET" --region "$REGION" >/dev/null 2>&1 || true
}
trap 'cleanup_bucket; rm -rf "$WORK"' EXIT
aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
  --create-bucket-configuration LocationConstraint="$REGION" >/dev/null
aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-encryption --bucket "$BUCKET" --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
aws s3 cp "$ART" "s3://$BUCKET/artifact.tar" --region "$REGION" >/dev/null
aws s3 cp deploy/ec2-release/deploy_on_ec2.sh "s3://$BUCKET/deploy_on_ec2.sh" --region "$REGION" >/dev/null
aws s3 cp deploy/ec2-release/rollback_on_ec2.sh "s3://$BUCKET/rollback_on_ec2.sh" --region "$REGION" >/dev/null
U_ART=$(aws s3 presign "s3://$BUCKET/artifact.tar" --expires-in 900 --region "$REGION")
U_DEP=$(aws s3 presign "s3://$BUCKET/deploy_on_ec2.sh" --expires-in 900 --region "$REGION")
U_RB=$(aws s3 presign "s3://$BUCKET/rollback_on_ec2.sh" --expires-in 900 --region "$REGION")

# Commands are passed as JSON so presigned URLs are never word-split.
PARAMS=$(python3 - "$RELEASE_ID" "$SHA" "$U_ART" "$U_DEP" "$U_RB" <<'PY'
import json, sys
rid, sha, art, dep, rb = sys.argv[1:]
d = f"/home/ubuntu/accessproof-releases/{rid}"
print(json.dumps({"executionTimeout": ["3600"], "commands": [
    "set -euo pipefail",
    f"install -d -m 700 /home/ubuntu/accessproof-releases {d}",
    f"curl -fsS -o {d}/artifact.tar '{art}'",
    f"curl -fsS -o {d}/deploy_on_ec2.sh '{dep}'",
    f"curl -fsS -o {d}/rollback_on_ec2.sh '{rb}'",
    f"echo '{sha}  {d}/artifact.tar' | sha256sum -c -",
    f"bash {d}/deploy_on_ec2.sh {rid} {d}/artifact.tar {sha}",
]}))
PY
)
CMD_ID=$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE" \
  --document-name AWS-RunShellScript --comment "AccessProof $RELEASE_ID" \
  --parameters "$PARAMS" --query Command.CommandId --output text)
echo "SSM command $CMD_ID"
while :; do
  STATUS=$(aws ssm get-command-invocation --region "$REGION" --command-id "$CMD_ID" \
    --instance-id "$INSTANCE" --query Status --output text 2>/dev/null || echo Pending)
  case "$STATUS" in Pending|InProgress|Delayed) sleep 15 ;; *) break ;; esac
done
aws ssm get-command-invocation --region "$REGION" --command-id "$CMD_ID" --instance-id "$INSTANCE" \
  --query '{Status:Status,Out:StandardOutputContent,Err:StandardErrorContent}' --output json
[[ "$STATUS" == Success ]]
