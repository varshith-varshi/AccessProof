#!/usr/bin/env bash
# Production releases only. Must use a separate, bounded AWS Roles Anywhere role.
# No AWS access is required for --dry-run; --preflight cannot modify production.
set -Eeuo pipefail
umask 077
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
REGION=eu-north-1
ACCOUNT=102076848988
INSTANCE=i-0c11427d4d9c1b438
BUCKET=accessproof-release-artifacts-102076848988-eu-north-1
ROLE=accessproof-production-deployer
PREFLIGHT=AccessProof-Deployer-ProductionPreflight
RELEASE_DOC=AccessProof-Deployer-ProductionRelease
MODE="${1:?Usage: ship_production.sh --dry-run|--preflight|--execute [commit] [label]}"
shift
COMMIT="${1:-HEAD}"
# A `web-` label selects the isolated web-only release in deploy_on_ec2.sh; any
# other label runs the full API, worker, web and migration release.
LABEL="${2:-web-r39-onboarding}"
[[ "$LABEL" =~ ^[a-z0-9][a-z0-9-]{5,40}$ ]] || { echo 'Bad release label' >&2; exit 2; }
cd "$REPO"
COMMIT=$(git rev-parse --verify "$COMMIT^{commit}")
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || exit 2
RID="$LABEL-${COMMIT:0:12}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

archive() {
  git archive --format=tar --add-virtual-file="RELEASE_COMMIT:$COMMIT" -o "$WORK/artifact.tar" "$COMMIT"
  tar -tf "$WORK/artifact.tar" | grep -Eiq '(^|/)\.env$|\.pem$|\.key$|\.dump$|\.zip$|credentials\.json$' \
    && { echo 'Refusing archive with secret-shaped paths' >&2; exit 2; }
  local archived_commit
  archived_commit=$(tar -xOf "$WORK/artifact.tar" RELEASE_COMMIT)
  [[ "$archived_commit" == "$COMMIT" ]] || { echo 'Commit provenance mismatch' >&2; exit 2; }
  SHA=$(sha256sum "$WORK/artifact.tar" | cut -d' ' -f1)
  echo "release=$RID commit=$COMMIT sha256=$SHA bytes=$(stat -c %s "$WORK/artifact.tar")"
}

awsrelease() { env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN AWS_PROFILE="$ROLE" aws "$@"; }
check_identity() {
  local arn
  arn=$(awsrelease sts get-caller-identity --query Arn --output text)
  [[ "$arn" == "arn:aws:sts::$ACCOUNT:assumed-role/$ROLE/$ROLE" ]] || { echo 'Wrong AWS role/session; refusing production release' >&2; exit 2; }
}

invoke() {
  local doc="$1" parameters="$2" id status
  id=$(awsrelease ssm send-command --region "$REGION" --instance-ids "$INSTANCE" \
      --document-name "$doc" --parameters "file://$parameters" \
      --comment "AccessProof pinned release $RID" --query Command.CommandId --output text)
  echo "SSM command submitted; ID=$id"
  for _ in {1..240}; do
    status=$(awsrelease ssm get-command-invocation --region "$REGION" --command-id "$id" --instance-id "$INSTANCE" --query Status --output text 2>/dev/null || echo Pending)
    case "$status" in Pending|InProgress|Delayed) sleep 15 ;; *) break ;; esac
  done
  awsrelease ssm get-command-invocation --region "$REGION" --command-id "$id" --instance-id "$INSTANCE" \
     --query '{Status:Status,Output:StandardOutputContent,Error:StandardErrorContent}' --output json > "$WORK/invocation.json"
  python3 - "$WORK/invocation.json" <<'PY'
import json,sys
j=json.load(open(sys.argv[1])); print('status=',j['Status']); print('stdout=',j.get('Output','')[-6000:]); print('stderr=',j.get('Error','')[-2200:])
PY
  [[ "$status" == Success ]] || return 1
}

preflight() {
  echo '{}' > "$WORK/params.json"
  invoke "$PREFLIGHT" "$WORK/params.json"
  python3 - "$WORK/invocation.json" <<'PY'
import json,re,sys
out=json.load(open(sys.argv[1]))['Output']
for key in ('DB_REVISION','DISK_FREE_GB','ZIP_SHA256'):
  values=re.findall(r'^'+key+r'=(\S+)$',out,re.M)
  if len(values)!=1: raise SystemExit('Missing unique preflight field: '+key)
  print('PREFLIGHT_'+key+'='+values[0])
PY
}

case "$MODE" in
 --dry-run) archive; echo 'DRY_RUN_PASS: no AWS service accessed'; exit 0 ;;
 --preflight) check_identity; preflight; exit 0 ;;
 --execute)
  [[ -z "$(git status --porcelain)" ]] || { echo 'Dirty checkout. Commit and retest first.' >&2; exit 2; }
  archive
  check_identity
  busy=$(awsrelease ssm list-commands --region "$REGION" --instance-id "$INSTANCE" \
    --query "Commands[?Status=='InProgress' || Status=='Pending'].[CommandId]" --output text)
  [[ -z "$busy" ]] || { echo 'Active SSM production work; refusing overlapping deployment' >&2; exit 2; }
  preflight
  RESULT=$(python3 - "$WORK/invocation.json" <<'PY'
import json,re,sys
out=json.load(open(sys.argv[1]))['Output']
def extract(k):
 m=re.findall(r'^'+k+r'=(\S+)$',out,re.M)
 if len(m)!=1: raise SystemExit('Missing '+k)
 return m[0]
rev=extract('DB_REVISION'); free=int(extract('DISK_FREE_GB')); z=extract('ZIP_SHA256')
if not re.fullmatch(r'[a-z0-9]{12}',rev): raise SystemExit('Invalid DB revision')
if free < 8: raise SystemExit('Insufficient production disk (<8 GB); no release attempted')
if z!='91a7c7d421316e882fe15003c8023bc4cc50de88cef9c6913c98cb887ae3df9a':
 raise SystemExit('Gateway ZIP checksum mismatch; no release attempted')
print(rev)
PY
  )
  awsrelease s3 cp "$WORK/artifact.tar" "s3://$BUCKET/releases/$RID.tar" --region "$REGION" --only-show-errors
  URL=$(awsrelease s3 presign "s3://$BUCKET/releases/$RID.tar" --region "$REGION" --expires-in 900)
  python3 - "$WORK/params.json" "$URL" "$RID" "$COMMIT" "$SHA" "$RESULT" <<'PY'
import base64,json,sys
out,url,rid,commit,sha,db=sys.argv[1:]
assert url.startswith('https://accessproof-release-artifacts-102076848988-eu-north-1.s3.eu-north-1.amazonaws.com/')
json.dump({'releaseId':[rid], 'commitSha':[commit], 'archiveSha256':[sha],
 'expectedDbRevision':[db], 'artifactUrlB64':[base64.b64encode(url.encode()).decode()]},open(out,'w'))
PY
  invoke "$RELEASE_DOC" "$WORK/params.json"
  echo "DEPLOYMENT_COMMAND_COMPLETE: $RID (verify Protect and public routes separately)"
  ;;
 *) echo 'Usage: --dry-run | --preflight | --execute [commit] [label]' >&2; exit 2 ;;
esac
