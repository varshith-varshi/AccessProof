#!/usr/bin/env bash
# AccessProof production release — runs ON the EC2 host (via SSM AWS-RunShellScript).
#
#   sudo bash deploy_on_ec2.sh <release-id> <artifact.tar> <expected-sha256>
#
# Deploys API + worker + web built from the exact source artifact, applies the
# release's Alembic migrations after a verified pg_dump, recreates ONLY api,
# worker and web (never db/redis/nginx), and rolls back automatically if any
# post-migration health gate fails. Never prints .env values.
set -Eeuo pipefail
umask 077

RELEASE_ID="${1:?release id}"; ARTIFACT="${2:?artifact}"; EXPECTED_SHA="${3:?sha256}"
# The pinned SSM release document always enters through this file. A `web-`
# release ID selects the isolated web-only release from the same checksummed
# artifact, leaving API, worker, db, redis and the schema untouched.
# A `guard-` release ID publishes the Guard bundle the same way.
if [[ "$RELEASE_ID" == guard-* ]]; then
  [[ "$(sha256sum "$ARTIFACT" | cut -d' ' -f1)" == "$EXPECTED_SHA" ]] || { echo "artifact checksum mismatch" >&2; exit 2; }
  GUARD_BUNDLE="$(dirname "$ARTIFACT")/deploy_guard_bundle_on_ec2.sh"
  tar -xOf "$ARTIFACT" deploy/ec2-release/deploy_guard_bundle_on_ec2.sh > "$GUARD_BUNDLE"
  chmod 700 "$GUARD_BUNDLE"
  exec bash "$GUARD_BUNDLE" "$RELEASE_ID" "$ARTIFACT" "$EXPECTED_SHA"
fi
# The API-only path loads reviewed API and worker images built off-host;
# never build web on the small live host or change the database schema.
if [[ "$RELEASE_ID" == api-* ]]; then
  [[ "$(sha256sum "$ARTIFACT" | cut -d' ' -f1)" == "$EXPECTED_SHA" ]] || { echo "artifact checksum mismatch" >&2; exit 2; }
  API_ONLY="$(dirname "$ARTIFACT")/deploy_api_only_on_ec2.sh"
  tar -xOf "$ARTIFACT" deploy/ec2-release/deploy_api_only_on_ec2.sh > "$API_ONLY"
  chmod 700 "$API_ONLY"
  exec bash "$API_ONLY" "$RELEASE_ID" "$ARTIFACT" "$EXPECTED_SHA"
fi
if [[ "$RELEASE_ID" == web-* ]]; then
  [[ "$(sha256sum "$ARTIFACT" | cut -d' ' -f1)" == "$EXPECTED_SHA" ]] || { echo "artifact checksum mismatch" >&2; exit 2; }
  WEB_ONLY="$(dirname "$ARTIFACT")/deploy_web_only_on_ec2.sh"
  tar -xOf "$ARTIFACT" deploy/ec2-release/deploy_web_only_on_ec2.sh > "$WEB_ONLY"
  chmod 700 "$WEB_ONLY"
  exec bash "$WEB_ONLY" "$RELEASE_ID" "$ARTIFACT" "$EXPECTED_SHA"
fi
APP_DIR=/home/ubuntu/accessproof
COMPOSE_FILE="$APP_DIR/docker-compose.ec2.yml"
REL="/home/ubuntu/accessproof-releases/$RELEASE_ID"
# The revision production must be at before this release. REQUIRED, no default:
# a stale default (r2b3c4d5e6f7) once outlived the r22 deploy. ship_via_ssm.sh
# passes it explicitly on the remote command line.
EXPECTED_DB_REVISION="${EXPECTED_DB_REVISION:?EXPECTED_DB_REVISION must be set to the current production Alembic revision}"
TARGET_DB_REVISION=""   # derived from the new API image's Alembic head
API_IMAGE="accessproof/api:$RELEASE_ID"
WORKER_IMAGE="accessproof/worker:$RELEASE_ID"
WEB_IMAGE="accessproof/web-v2:$RELEASE_ID"
MIGRATED=0
PUBLIC_CHECKS="${PUBLIC_CHECKS:-1}"                  # 0 only for an offline rehearsal
REUSE_EXISTING_IMAGES="${REUSE_EXISTING_IMAGES:-0}"  # 1 only for an offline rehearsal
# Reviewed production Gateway ZIP (observed directly 2026-11-05). The release
# tar intentionally excludes ZIPs; copy this public, non-secret installer from
# the currently running web image into the new build, and pin its content.
EXPECTED_GATEWAY_INSTALLER_SHA256="e0e78f53cf0c161044b6054ed50ac539b4feb27507503ffb339a430ddacbfba4"

[[ "$RELEASE_ID" =~ ^[a-z0-9][a-z0-9.-]{5,80}$ ]] || { echo "bad release id"; exit 2; }
[[ "$EXPECTED_DB_REVISION" =~ ^[0-9a-z]{12}$ ]] || { echo "bad EXPECTED_DB_REVISION"; exit 2; }
# One release operation at a time on this host (deploy, rollback, DB-role
# switch), whoever starts it: operator, SSM, or an agent.
install -d -m 700 /home/ubuntu/accessproof-releases
exec 9>>/home/ubuntu/accessproof-releases/.release.lock
flock -n 9 || { echo "another release operation holds the host release lock: $(cat /home/ubuntu/accessproof-releases/.release.lock.holder 2>/dev/null)" >&2; exit 75; }
printf '%s pid=%s %s %s\n' "$(date -u +%FT%TZ)" "$$" "$(basename "$0")" "$RELEASE_ID" > /home/ubuntu/accessproof-releases/.release.lock.holder
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$REL/deployment-logs/deploy.log"; }
compose() { docker compose --project-directory "$APP_DIR" -f "$COMPOSE_FILE" "$@"; }
env_value() { grep -E "^$1=" "$APP_DIR/.env" | tail -1 | cut -d= -f2-; }   # only for image refs
# Migrations need DDL, so they always run as the table OWNER — never via the
# api service's runtime DATABASE_URL, which after the P0-01 switch is the
# restricted accessproof_app role. The password travels in the environment
# (compose run -e NAME), never in argv, so it never appears in `ps`.
owner_alembic() {  # <api-image> <alembic args...>
  local image="$1"; shift
  local pw; pw=$(grep -E '^POSTGRES_PASSWORD=' "$APP_DIR/.env" | tail -1 | cut -d= -f2- | sed -E "s/^['\"]//; s/['\"]$//")
  [[ -n "$pw" ]] || { echo "POSTGRES_PASSWORD missing from .env" >&2; return 1; }
  DATABASE_URL="postgresql+psycopg://accessproof:${pw}@db:5432/accessproof" ACCESSPROOF_API_IMAGE="$image" \
    compose run --rm --no-deps -T -e DATABASE_URL api alembic "$@"
}
db_revision() { compose exec -T db psql -U accessproof -d accessproof -tAc "select version_num from alembic_version" | tr -d '[:space:]'; }

wait_healthy() {  # <service> <seconds>
  local svc=$1 deadline=$((SECONDS + $2)) cid state
  while (( SECONDS < deadline )); do
    cid=$(compose ps -q "$svc" || true)
    if [[ -n "$cid" ]]; then
      state=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid")
      [[ "$state" == healthy || ( "$svc" == worker && "$state" == running ) ]] && return 0
    fi
    sleep 3
  done
  return 1
}

rollback() {
  log "ROLLBACK: restoring previous image references"
  cp "$REL/rollback/.env" "$APP_DIR/.env"
  if (( MIGRATED )); then
    if [[ "$(compose exec -T db psql -U accessproof -d accessproof -tAc \
          "select count(*) from source_effective_certifications where length(signature) > 64" | tr -d '[:space:]')" != "0" ]]; then
      log "ROLLBACK HALTED: Ed25519 certificates exist; downgrade would delete them. Manual decision required."
      exit 3
    fi
    log "ROLLBACK: alembic downgrade $EXPECTED_DB_REVISION"
    owner_alembic "$API_IMAGE" downgrade "$EXPECTED_DB_REVISION" >>"$REL/deployment-logs/rollback-migration.log" 2>&1
  fi
  compose up -d --no-deps --force-recreate api >>"$REL/deployment-logs/rollback.log" 2>&1
  wait_healthy api 240 || { log "ROLLBACK: previous API not healthy — escalate"; exit 4; }
  compose up -d --no-deps --force-recreate worker web >>"$REL/deployment-logs/rollback.log" 2>&1
  wait_healthy worker 120 && wait_healthy web 180 && log "ROLLBACK COMPLETE: previous release healthy" || log "ROLLBACK: worker/web unhealthy — escalate"
  exit 1
}

# ---------------------------------------------------------------- preflight
mkdir -p "$REL"/{rollback,build-logs,deployment-logs,backup,src}
chmod 700 /home/ubuntu/accessproof-releases "$REL"
log "release $RELEASE_ID starting"
[[ "$(sha256sum "$ARTIFACT" | cut -d' ' -f1)" == "$EXPECTED_SHA" ]] || { log "artifact checksum mismatch"; exit 2; }
avail_gb=$(df -BG --output=avail / | tail -1 | tr -dc 0-9)
(( avail_gb >= 8 )) || { log "insufficient disk: ${avail_gb}G free (need 8G)"; exit 2; }
for svc in db redis api; do wait_healthy "$svc" 10 || { log "preflight: $svc not healthy; refusing to deploy"; exit 2; }; done
current_rev=$(db_revision)
[[ "$current_rev" == "$EXPECTED_DB_REVISION" ]] || { log "unexpected DB revision $current_rev"; exit 2; }

# ----------------------------------------------------------- rollback state
cp -p "$APP_DIR/.env" "$REL/rollback/.env"; cp -p "$COMPOSE_FILE" "$REL/rollback/docker-compose.ec2.yml"
chmod 600 "$REL/rollback/.env"
{
  echo "previous_api_image=$(env_value ACCESSPROOF_API_IMAGE)"
  echo "previous_web_image=$(env_value ACCESSPROOF_WEB_IMAGE)"
  echo "previous_worker_image=$(env_value ACCESSPROOF_WORKER_IMAGE)"
  echo "previous_db_revision=$current_rev"
  compose ps --format '{{.Service}} {{.Image}} {{.Status}}'
  docker images --digests --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.Digest}}' | grep '^accessproof/'
} > "$REL/rollback/previous-state.txt"
echo "$EXPECTED_SHA  $(basename "$ARTIFACT")" > "$REL/checksums.txt"

# -------------------------------------------------------------------- build
tar -xf "$ARTIFACT" -C "$REL/src"
cat "$REL/src/RELEASE_COMMIT" > "$REL/source-commit.txt" 2>/dev/null || true

preserve_reviewed_gateway_installer() {
  # A plain Git rebuild omits the production ZIP: it is a ~98 MB runtime
  # artifact, intentionally absent from the source checkout and release tar.
  # Production MUST fail before image/migration work rather than publish 404.
  local cid target digest
  if [[ "$PUBLIC_CHECKS" == 0 ]]; then
    log "rehearsal: production installer ZIP preservation is not required"
    return 0
  fi
  cid=$(compose ps -q web || true)
  if [[ -z "$cid" ]]; then
    log "RELEASE REFUSED: no prior production web container to supply reviewed Gateway ZIP"
    return 2
  fi
  install -d -m 700 "$REL/src/web-v2/public/downloads"
  target="$REL/src/web-v2/public/downloads/accessproof-gateway-connector.zip"
  [[ ! -e "$target" && ! -L "$target" ]] || { log "RELEASE REFUSED: release archive unexpectedly contains installer ZIP"; return 2; }
  if ! docker cp "$cid:/app/public/downloads/accessproof-gateway-connector.zip" "$target" >/dev/null 2>&1; then
    log "RELEASE REFUSED: current production installer ZIP is missing"
    return 2
  fi
  [[ -f "$target" && ! -L "$target" ]] || { log "RELEASE REFUSED: copied installer is not a regular file"; return 2; }
  digest=$(sha256sum "$target" | awk '{print $1}')
  [[ "$digest" == "$EXPECTED_GATEWAY_INSTALLER_SHA256" ]] || {
    log "RELEASE REFUSED: current installer checksum differs from reviewed artifact; review a fresh release first"
    return 2
  }
  python3 - "$target" <<'PYZIP'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as bundle:
    required = {'__main__.py', 'accessproof-gateway-connector/accessproof-gateway-runtime.tar.gz'}
    if not required.issubset(bundle.namelist()) or bundle.testzip() is not None:
        raise SystemExit('RELEASE REFUSED: existing installer integrity verification failed')
PYZIP
  printf '%s  %s\n' "$digest" 'web-v2/public/downloads/accessproof-gateway-connector.zip' >> "$REL/checksums.txt"
  log "reviewed Gateway installer preserved for new web image (SHA-256 pinned)"
}
preserve_reviewed_gateway_installer
if [[ "$REUSE_EXISTING_IMAGES" == 1 ]] && docker image inspect "$API_IMAGE" "$WORKER_IMAGE" "$WEB_IMAGE" >/dev/null 2>&1; then
  log "rehearsal: reusing pre-built release images"
else
  docker build -f "$REL/src/apps/api/Dockerfile" -t "$API_IMAGE" "$REL/src" >"$REL/build-logs/api.log" 2>&1
  docker build -f "$REL/src/apps/worker/Dockerfile" -t "$WORKER_IMAGE" "$REL/src" >"$REL/build-logs/worker.log" 2>&1
  docker build -t "$WEB_IMAGE" "$REL/src/web-v2" >"$REL/build-logs/web.log" 2>&1
fi
for img in "$API_IMAGE" "$WORKER_IMAGE"; do
  docker run --rm --entrypoint test "$img" -f /app/apps/api/accessproof_api/gateway_presence.py
done
docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | grep ":$RELEASE_ID" >> "$REL/checksums.txt"
TARGET_DB_REVISION=$(docker run --rm --entrypoint alembic "$API_IMAGE" heads 2>/dev/null | awk '/\(head\)/{print $1}')
[[ "$TARGET_DB_REVISION" =~ ^[0-9a-z]{12}$ ]] || { log "could not determine target revision"; exit 2; }
log "images built; target DB revision $TARGET_DB_REVISION"

# ------------------------------------------------- verified database backup
compose exec -T db pg_dump -U accessproof -d accessproof -Fc > "$REL/backup/pre-$RELEASE_ID.dump"
entries=$(compose exec -T db pg_restore --list < "$REL/backup/pre-$RELEASE_ID.dump" | grep -c ' TABLE DATA ' || true)
(( entries > 10 )) || { log "backup verification failed ($entries table-data entries)"; exit 2; }
sha256sum "$REL/backup/pre-$RELEASE_ID.dump" >> "$REL/checksums.txt"
log "backup verified ($entries table-data entries)"

trap 'log "failure at line $LINENO"; rollback' ERR

# ---------------------------------------------------------------- migrate
owner_alembic "$API_IMAGE" upgrade head >"$REL/deployment-logs/migration.log" 2>&1
# A web-only/code-only release must NOT be classified as a DB migration.
# Otherwise rollback incorrectly enters the Ed25519-downgrade guard even
# though the schema never changed, blocking restoration of the previous web.
if [[ "$current_rev" != "$TARGET_DB_REVISION" ]]; then MIGRATED=1; fi
[[ "$(db_revision)" == "$TARGET_DB_REVISION" ]]
log "database at $TARGET_DB_REVISION"

# ----------------------------------------------- switch image references
tmp="$APP_DIR/.env.release-$RELEASE_ID"
cp -p "$APP_DIR/.env" "$tmp"
sed -i -E "s#^ACCESSPROOF_API_IMAGE=.*#ACCESSPROOF_API_IMAGE=$API_IMAGE#; s#^ACCESSPROOF_WORKER_IMAGE=.*#ACCESSPROOF_WORKER_IMAGE=$WORKER_IMAGE#; s#^ACCESSPROOF_WEB_IMAGE=.*#ACCESSPROOF_WEB_IMAGE=$WEB_IMAGE#" "$tmp"
for k in API WORKER WEB; do grep -q "^ACCESSPROOF_${k}_IMAGE=" "$tmp"; done
mv "$tmp" "$APP_DIR/.env"

# --------------------------------------------- ordered recreate + gates
compose up -d --no-deps --force-recreate api >>"$REL/deployment-logs/deploy.log" 2>&1
wait_healthy api 240
compose up -d --no-deps --force-recreate worker >>"$REL/deployment-logs/deploy.log" 2>&1
wait_healthy worker 120
compose up -d --no-deps --force-recreate web >>"$REL/deployment-logs/deploy.log" 2>&1
wait_healthy web 180
if [[ "$PUBLIC_CHECKS" == 1 ]]; then
  new_installer_sha=$(compose exec -T web sha256sum /app/public/downloads/accessproof-gateway-connector.zip | awk '{print $1}')
  [[ "$new_installer_sha" == "$EXPECTED_GATEWAY_INSTALLER_SHA256" ]] || {
    log "RELEASE REFUSED: the new web image lost the reviewed Gateway installer"; false;
  }
fi

# --------------------------------------------- internal verification gates
api_probe() {  # <method> <path> -> HTTP status from inside the API container
  compose exec -T api python -c "import sys,urllib.request as u
r=u.Request('http://127.0.0.1:8000'+sys.argv[2],method=sys.argv[1],data=(b'{}' if sys.argv[1]=='POST' else None),headers={'Host':'api.accessproof.in','Content-Type':'application/json'})
try: print(u.urlopen(r).status)
except u.HTTPError as e: print(e.code)" "$1" "$2"
}
[[ "$(api_probe GET /health/ready)" == 200 ]]
[[ "$(api_probe POST /api/v1/gateway-installations/heartbeat)" == 422 ]]   # new route present
[[ "$(api_probe GET /api/v1/guards)" == 401 ]]                              # auth still enforced
compose exec -T web wget -q -O /dev/null http://127.0.0.1:3000/login
# ----------------------------------------------- public verification gates
if [[ "$PUBLIC_CHECKS" == 1 ]]; then
  curl -fsS --max-time 15 https://api.accessproof.in/health/ready | tee "$REL/deployment-logs/health-ready.json" | grep -q '"ready"'
  curl -fsS --max-time 15 -o /dev/null https://app.accessproof.in/login
  # An arbitrary session-cookie value must NOT grant customer ZIP access.
  installer_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
    -H 'Cookie: accessproof_session=synthetic-invalid-no-real-session' \
    https://app.accessproof.in/downloads/accessproof-gateway-connector.zip)
  [[ "$installer_status" == 307 || "$installer_status" == 302 || "$installer_status" == 401 || "$installer_status" == 403 ]]
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST -H 'Content-Type: application/json' \
    -d '{}' https://api.accessproof.in/api/v1/gateway-installations/heartbeat)
  [[ "$code" == 422 ]]   # new route reachable through nginx; schema enforced
fi
for svc in api worker web; do
  [[ "$(docker inspect -f '{{.Config.Image}}' "$(compose ps -q $svc)")" == *":$RELEASE_ID" ]]
done
trap - ERR
compose ps --format '{{.Service}} {{.Image}} {{.Status}}' > "$REL/deployment-logs/post-deploy-ps.txt"
log "DEPLOYMENT VERIFIED: api/worker/web on $RELEASE_ID, db $TARGET_DB_REVISION"
