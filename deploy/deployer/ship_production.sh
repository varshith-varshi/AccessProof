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
GATEWAY_ZIP_SHA=d0226438e6f255ef4dc5079ba894b57b47db7e5924dfaa9e94ffb9bcb0ef0b3d
PREVIOUS_GATEWAY_ZIP_SHA=e0e78f53cf0c161044b6054ed50ac539b4feb27507503ffb339a430ddacbfba4
SDK_FILE=accessproof_rag-0.1.0-py3-none-any.whl
SDK_SHA=ce72587503532202add008990e59fbf2a9c1c23e3740e1a4be3fac4b37235072
GATEWAY_ZIP="${GATEWAY_ZIP:-$HOME/Downloads/accessproof-gateway-connector-20261107-multirag-ports.zip}"
MODE="${1:?Usage: ship_production.sh --dry-run|--build-image|--preflight|--execute [commit] [label]}"
shift
COMMIT="${1:-HEAD}"
# A `web-` label selects the isolated web-only release in deploy_on_ec2.sh; any
# other label runs the full API, worker, web and migration release.
LABEL="${2:-web-r44-challenge}"
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

# Build the web image here, never on the 2 GB production host, then add it to the
# artifact so the release checksum covers it. The Gateway ZIP is not in Git and
# must match the reviewed digest.
bundle_web_image() {
  local image="accessproof/web-v2:$RID" context="$WORK/context" out="$WORK/image" expected actual
  [[ "$(sha256sum "$GATEWAY_ZIP" | cut -d' ' -f1)" == "$GATEWAY_ZIP_SHA" ]] || { echo 'Gateway ZIP missing or not the reviewed digest' >&2; exit 2; }
  install -d -m 700 "$context" "$out"
  git archive --format=tar "$COMMIT" web-v2 | tar -xf - -C "$context"
  cp "$GATEWAY_ZIP" "$context/web-v2/public/downloads/accessproof-gateway-connector.zip"
  if docker image inspect "$image" >/dev/null 2>&1; then docker image rm "$image" >/dev/null; fi
  docker build --platform linux/amd64 -t "$image" "$context/web-v2" > "$WORK/web-build.log" 2>&1 \
    || { tail -30 "$WORK/web-build.log" >&2; echo 'Off-host web build failed' >&2; exit 2; }
  [[ "$(docker image inspect -f '{{.Architecture}}' "$image")" == amd64 ]] || { echo 'Image is not amd64' >&2; exit 2; }
  for expected in "$GATEWAY_ZIP_SHA  /app/public/downloads/accessproof-gateway-connector.zip" "$SDK_SHA  /app/public/downloads/$SDK_FILE"; do
    actual=$(docker run --rm --entrypoint sha256sum "$image" "${expected#*  }" | awk '{print $1}')
    [[ "$actual" == "${expected%%  *}" ]] || { echo 'Image lost a reviewed download' >&2; exit 2; }
  done
  docker save --platform linux/amd64 "$image" | gzip -6 > "$out/web-image.tar.gz"
  # The image ID differs between Docker's classic and containerd stores, so
  # approve each identity of this same image; the artifact checksum binds them.
  python3 "$HERE/image_digests.py" "$out/web-image.tar.gz" "$(docker image inspect -f '{{.Id}}' "$image")" > "$out/web-image.digests"
  tar -rf "$WORK/artifact.tar" -C "$out" web-image.tar.gz web-image.digests
  SHA=$(sha256sum "$WORK/artifact.tar" | cut -d' ' -f1)
  echo "bundled image=$image bytes=$(stat -c %s "$WORK/artifact.tar") sha256=$SHA"
  sed 's/^/approved_digest=/' "$out/web-image.digests"
}


# API/worker images are also built OFF the 2 GB EC2 host.  The full release
# script still builds web on-host, so API-only releases use a separate isolated
# server entrypoint that NEVER rebuilds or recreates web or changes the DB.
bundle_api_images() {
  local context="$WORK/context" out="$WORK/images" svc image digest
  install -d -m 700 "$context" "$out"
  git archive --format=tar "$COMMIT" | tar -xf - -C "$context"
  # This script runs under umask 077; git archive extraction would create
  # root-owned, unreadable application directories inside the Docker image.
  # The release archive contains tracked source only, never private secrets.
  # Keep the staged build context private while making copied source readable
  # to API/worker's non-root UID 10001.
  chmod -R u+rwX,go+rX "$context"
  for svc in api worker; do
    image="accessproof/$svc:$RID"
    # Local pre-build and execute may run sequentially for the same commit.
    # Remove only that uniquely named local build tag, never the production image.
    if docker image inspect "$image" >/dev/null 2>&1; then
      docker image rm "$image" >/dev/null
    fi
    docker build --platform linux/amd64 -f "$context/apps/$svc/Dockerfile" \
      -t "$image" "$context" > "$WORK/$svc-build.log" 2>&1 \
      || { tail -40 "$WORK/$svc-build.log" >&2; echo "$svc off-host build failed" >&2; exit 2; }
    [[ "$(docker image inspect -f '{{.Architecture}}' "$image")" == amd64 ]] || exit 2
    docker run --rm --entrypoint test "$image" -f /app/apps/api/accessproof_api/gateway_presence.py
    docker save --platform linux/amd64 "$image" | gzip -6 > "$out/$svc-image.tar.gz"
    python3 "$HERE/image_digests.py" "$out/$svc-image.tar.gz" \
      "$(docker image inspect -f '{{.Id}}' "$image")" > "$out/$svc-image.digests"
    digest="$(docker image inspect -f '{{.Id}}' "$image")"
    echo "API_BUNDLE_IMAGE $svc $digest"
  done
  tar -rf "$WORK/artifact.tar" -C "$out" api-image.tar.gz api-image.digests \
    worker-image.tar.gz worker-image.digests
  SHA=$(sha256sum "$WORK/artifact.tar" | cut -d' ' -f1)
  echo "API/worker off-host image bundle bytes=$(stat -c %s "$WORK/artifact.tar") sha256=$SHA"
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
 --build-image)
  [[ "$RID" != web-* ]] || python3 "$REPO/scripts/verify_release_installer_pins.py" --zip "$GATEWAY_ZIP"
  archive
  if [[ "$RID" == api-* ]]; then bundle_api_images; else bundle_web_image; fi
  echo 'BUILD_PASS: no AWS service accessed'; exit 0 ;;
 --preflight) check_identity; preflight; exit 0 ;;
 --execute)
  [[ -z "$(git status --porcelain)" ]] || { echo 'Dirty checkout. Commit and retest first.' >&2; exit 2; }
  # Verify *all* server-side pins before uploading a candidate web image.
  [[ "$RID" != web-* ]] || python3 "$REPO/scripts/verify_release_installer_pins.py" --zip "$GATEWAY_ZIP"
  archive
  check_identity
  busy=$(awsrelease ssm list-commands --region "$REGION" --instance-id "$INSTANCE" \
    --query "Commands[?Status=='InProgress' || Status=='Pending'].[CommandId]" --output text)
  [[ -z "$busy" ]] || { echo 'Active SSM production work; refusing overlapping deployment' >&2; exit 2; }
  preflight
  RESULT=$(python3 - "$WORK/invocation.json" "$GATEWAY_ZIP_SHA" "$PREVIOUS_GATEWAY_ZIP_SHA" <<'PY'
import json,re,sys
out=json.load(open(sys.argv[1]))['Output']
def extract(k):
 m=re.findall(r'^'+k+r'=(\S+)$',out,re.M)
 if len(m)!=1: raise SystemExit('Missing '+k)
 return m[0]
rev=extract('DB_REVISION'); free=int(extract('DISK_FREE_GB')); z=extract('ZIP_SHA256')
if not re.fullmatch(r'[a-z0-9]{12}',rev): raise SystemExit('Invalid DB revision')
if free < 8: raise SystemExit('Insufficient production disk (<8 GB); no release attempted')
if z not in sys.argv[2:]:
 raise SystemExit('Gateway ZIP checksum mismatch; no release attempted')
print(rev)
PY
  )
  if [[ "$RID" == web-* ]]; then bundle_web_image
  elif [[ "$RID" == api-* ]]; then bundle_api_images
  fi
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
 *) echo 'Usage: --dry-run | --build-image | --preflight | --execute [commit] [label]' >&2; exit 2 ;;
esac
