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
APP_DIR=/home/ubuntu/accessproof
COMPOSE_FILE="$APP_DIR/docker-compose.ec2.yml"
REL="/home/ubuntu/accessproof-releases/$RELEASE_ID"
# The revision production must be at before this release (r21 = r2b3c4d5e6f7).
EXPECTED_DB_REVISION="${EXPECTED_DB_REVISION:-r2b3c4d5e6f7}"
TARGET_DB_REVISION=""   # derived from the new API image's Alembic head
API_IMAGE="accessproof/api:$RELEASE_ID"
WORKER_IMAGE="accessproof/worker:$RELEASE_ID"
WEB_IMAGE="accessproof/web-v2:$RELEASE_ID"
MIGRATED=0
PUBLIC_CHECKS="${PUBLIC_CHECKS:-1}"                  # 0 only for an offline rehearsal
REUSE_EXISTING_IMAGES="${REUSE_EXISTING_IMAGES:-0}"  # 1 only for an offline rehearsal

[[ "$RELEASE_ID" =~ ^[a-z0-9][a-z0-9.-]{5,80}$ ]] || { echo "bad release id"; exit 2; }
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$REL/deployment-logs/deploy.log"; }
compose() { docker compose --project-directory "$APP_DIR" -f "$COMPOSE_FILE" "$@"; }
env_value() { grep -E "^$1=" "$APP_DIR/.env" | tail -1 | cut -d= -f2-; }   # only for image refs
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
    ACCESSPROOF_API_IMAGE="$API_IMAGE" compose run --rm --no-deps -T api alembic downgrade "$EXPECTED_DB_REVISION" \
      >>"$REL/deployment-logs/rollback-migration.log" 2>&1
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
ACCESSPROOF_API_IMAGE="$API_IMAGE" compose run --rm --no-deps -T api alembic upgrade head \
  >"$REL/deployment-logs/migration.log" 2>&1
MIGRATED=1
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
