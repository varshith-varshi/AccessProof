#!/usr/bin/env bash
# Operator workstation: ship a git-committed AccessProof release to EC2 via
# private S3 + AWS Systems Manager, then run deploy_on_ec2.sh there.
#
#   bash deploy/ec2-release/ship_via_ssm.sh <git-commit> <expected-db-revision> <release-label>
#
#   e.g. bash deploy/ec2-release/ship_via_ssm.sh 87e6a83 u5e6f7a8b9c0 r23-rt-fixes
#
# <expected-db-revision> is the Alembic revision production is at NOW (read it
# with a read-only SSM check first). It is passed explicitly into the remote
# command; deploy_on_ec2.sh refuses to run on any other revision.
# The release id is "<release-label>-<commit12>" and must not already exist on
# the host.
#
# Requires valid AWS credentials for account 102076848988. Makes NO IAM,
# security-group or instance changes: the instance downloads the artifact
# with a 15-minute presigned URL. The temporary bucket blocks public access,
# uses SSE-S3, and is deleted at the end.
set -Eeuo pipefail
umask 077
COMMIT=$(git rev-parse --verify "${1:?usage: ship_via_ssm.sh <git-commit> <expected-db-revision> <release-label>}^{commit}")
EXPECTED_DB_REVISION="${2:?expected DB revision (the Alembic revision production is at now)}"
LABEL="${3:?release label, e.g. r23-rt-fixes}"
[[ "$EXPECTED_DB_REVISION" =~ ^[0-9a-z]{12}$ ]] || { echo "bad expected DB revision"; exit 2; }
[[ "$LABEL" =~ ^[a-z0-9][a-z0-9-]{1,40}$ ]] || { echo "bad release label"; exit 2; }
ACCOUNT=102076848988; REGION=eu-north-1; PRODUCTION_INSTANCE=i-0c11427d4d9c1b438
INSTANCE=$PRODUCTION_INSTANCE; PAYLOAD_MODE=()
# Rehearsal: the identical path against a staging instance. Public checks are
# disabled there (they would probe production's URLs and pass misleadingly).
if [[ -n "${ACCESSPROOF_REHEARSAL_INSTANCE:-}" ]]; then
  [[ "$ACCESSPROOF_REHEARSAL_INSTANCE" =~ ^i-[0-9a-f]{8,17}$ ]] || { echo "bad rehearsal instance id"; exit 2; }
  [[ "$ACCESSPROOF_REHEARSAL_INSTANCE" != "$PRODUCTION_INSTANCE" ]] || { echo "rehearsal instance must not be production"; exit 2; }
  INSTANCE=$ACCESSPROOF_REHEARSAL_INSTANCE; PAYLOAD_MODE=(--rehearsal-no-public-checks)
  echo "*** REHEARSAL against $INSTANCE (not production); public checks disabled ***"
fi
RELEASE_ID="${LABEL}-${COMMIT:0:12}"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

[[ "$(aws sts get-caller-identity --query Account --output text)" == "$ACCOUNT" ]] \
  || { echo "wrong AWS account"; exit 2; }
[[ -z "$(git status --porcelain)" ]] || echo "note: working tree dirty; shipping committed $COMMIT only"
aws ssm describe-instance-information --region "$REGION" \
  --filters "Key=InstanceIds,Values=$INSTANCE" --query 'InstanceInformationList[0].PingStatus' --output text \
  | grep -qx Online || { echo "instance not SSM-online"; exit 2; }
# Never overlap another operator or agent: refuse while any SSM command is
# still running on the instance. (The host scripts also take a flock.)
busy=$(aws ssm list-commands --region "$REGION" --instance-id "$INSTANCE" \
  --query "Commands[?Status=='InProgress' || Status=='Pending'].[CommandId,Comment]" --output text)
[[ -z "$busy" ]] || { echo "SSM commands still running on $INSTANCE; refusing:"; echo "$busy"; exit 2; }

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
# Host scripts come from the SAME pinned commit as the artifact, never from
# the working tree, so what runs on the host is traceable to $COMMIT.
for f in deploy_on_ec2.sh rollback_on_ec2.sh enable_least_privilege_db.sh \
         patch_compose_db_roles.py run_security_gates.sh ssm_payload.py; do
  git show "$COMMIT:deploy/ec2-release/$f" > "$WORK/$f"
done
for f in deploy_on_ec2.sh rollback_on_ec2.sh enable_least_privilege_db.sh \
         patch_compose_db_roles.py run_security_gates.sh; do
  aws s3 cp "$WORK/$f" "s3://$BUCKET/$f" --region "$REGION" >/dev/null
done
U_ART=$(aws s3 presign "s3://$BUCKET/artifact.tar" --expires-in 900 --region "$REGION")
U_DEP=$(aws s3 presign "s3://$BUCKET/deploy_on_ec2.sh" --expires-in 900 --region "$REGION")
U_RB=$(aws s3 presign "s3://$BUCKET/rollback_on_ec2.sh" --expires-in 900 --region "$REGION")
U_DB=$(aws s3 presign "s3://$BUCKET/enable_least_privilege_db.sh" --expires-in 900 --region "$REGION")
U_PC=$(aws s3 presign "s3://$BUCKET/patch_compose_db_roles.py" --expires-in 900 --region "$REGION")
U_GT=$(aws s3 presign "s3://$BUCKET/run_security_gates.sh" --expires-in 900 --region "$REGION")

# Commands are passed as JSON so presigned URLs are never word-split. The
# wrapper runs under /bin/sh; see ssm_payload.py.
PARAMS=$(python3 "$WORK/ssm_payload.py" "${PAYLOAD_MODE[@]}" "$RELEASE_ID" "$SHA" "$EXPECTED_DB_REVISION" \
  "$U_ART" "$U_DEP" "$U_RB" "$U_DB" "$U_PC" "$U_GT")
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
