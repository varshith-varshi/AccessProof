#!/usr/bin/env bash
# AccessProof Guard bundle release via the pinned SSM production document.
# Adds one reviewed file to the exact API image already running, so API code and
# dependencies stay byte-identical. Nothing is built: an unlocked `pip install`
# could change dependencies, and a build took production down on 2026-11-05.
# Recreates only api. No worker, web, db or redis change, and no migration.
set -Eeuo pipefail
umask 077
RELEASE_ID="${1:?release id}"; ARCHIVE="${2:?release tar}"; EXPECTED_SHA="${3:?archive sha256}"
EXPECTED_DB_REVISION="${EXPECTED_DB_REVISION:?expected production database revision required}"
[[ "${PUBLIC_CHECKS:-1}" == 1 ]] || { echo 'Production release requires public checks' >&2; exit 2; }
[[ "$RELEASE_ID" =~ ^[a-z0-9][a-z0-9.-]{5,80}$ ]] || exit 2
[[ "$EXPECTED_DB_REVISION" =~ ^[a-z0-9]{12}$ && "$EXPECTED_SHA" =~ ^[a-f0-9]{64}$ ]] || exit 2
GUARD_VERSION=0.1.6
BUNDLE="accessproof-guard-$GUARD_VERSION.tar.gz"
APP_DIR=/home/ubuntu/accessproof
COMPOSE="$APP_DIR/docker-compose.ec2.yml"
REL="/home/ubuntu/accessproof-releases/$RELEASE_ID"
NEW_API_IMAGE="accessproof/api:$RELEASE_ID"
MIN_AVAILABLE_MB=300
log(){ printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
compose(){ docker compose --project-directory "$APP_DIR" -f "$COMPOSE" "$@"; }
public_status(){ curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "$1" 2>/dev/null || true; }
db_revision(){ compose exec -T db psql -U accessproof -d accessproof -tAc 'select version_num from alembic_version' | tr -d '[:space:]'; }
reload_nginx(){ compose exec -T nginx nginx -t && compose exec -T nginx nginx -s reload; }
wait_api(){
  local cid state deadline=$((SECONDS + 240))
  while (( SECONDS < deadline )); do
    cid=$(compose ps -q api || true)
    if [[ -n "$cid" ]]; then
      state=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid")
      [[ "$state" == healthy ]] && return 0
    fi
    sleep 3
  done
  return 1
}
rollback(){
  local code=$?
  trap - ERR
  log 'GUARD BUNDLE RELEASE FAILED: restoring previous API image and environment'
  if [[ -f "$REL/rollback/.env" ]]; then
    cp -p "$REL/rollback/.env" "$APP_DIR/.env"
    if compose up -d --no-deps --force-recreate api >>"$REL/rollback/api-restore.log" 2>&1 \
      && wait_api && reload_nginx >>"$REL/rollback/api-restore.log" 2>&1 \
      && [[ "$(public_status https://api.accessproof.in/health/ready)" == 200 ]]; then
      log 'API ROLLBACK VERIFIED: previous API image healthy'
    else
      log 'CRITICAL: API ROLLBACK NOT VERIFIED; immediate operator intervention required' >&2
    fi
  fi
  exit "${code:-1}"
}
install -d -m 700 /home/ubuntu/accessproof-releases
exec 9>>/home/ubuntu/accessproof-releases/.release.lock
flock -n 9 || { log 'Another release holds production release lock'; exit 75; }
install -d -m 700 "$REL" "$REL/src" "$REL/rollback" "$REL/logs"
log "Production Guard bundle release $RELEASE_ID starting"
[[ "$(public_status https://app.accessproof.in/login)" == 200 ]] || { log 'Public website unreachable before release; production untouched'; exit 2; }
[[ "$(public_status https://api.accessproof.in/health/ready)" == 200 ]] || { log 'Public API unreachable before release; production untouched'; exit 2; }
[[ "$(sha256sum "$ARCHIVE" | awk '{print $1}')" == "$EXPECTED_SHA" ]] || { log 'Archive checksum mismatch'; exit 2; }
[[ ! -e "$REL/rollback/.env" ]] || { log 'This release ID was used before'; exit 2; }
available_mb=$(awk '/^MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo)
(( available_mb >= MIN_AVAILABLE_MB )) || { log "Only ${available_mb}MB memory available; need ${MIN_AVAILABLE_MB}MB"; exit 2; }
current_rev=$(db_revision)
[[ "$current_rev" == "$EXPECTED_DB_REVISION" ]] || { log 'Database revision changed since authorization'; exit 2; }
for service in db redis api web; do
  cid=$(compose ps -q "$service"); [[ -n "$cid" ]] || { log "Missing $service container"; exit 2; }
  state=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid")
  [[ "$state" == healthy ]] || { log "$service not healthy ($state)"; exit 2; }
done
for service in db redis web worker nginx; do printf '%s=%s\n' "$service" "$(compose ps -q "$service")"; done >"$REL/rollback/unmodified-service-ids.txt"
tar -xf "$ARCHIVE" -C "$REL/src" "packaging/guard/releases/$BUNDLE" "packaging/guard/releases/$BUNDLE.sha256"
( cd "$REL/src/packaging/guard/releases" && sha256sum -c "$BUNDLE.sha256" >/dev/null ) || { log 'Guard bundle checksum mismatch; production untouched'; exit 2; }
chmod 644 "$REL/src/packaging/guard/releases/$BUNDLE"
old_api_image=$(docker inspect -f '{{.Config.Image}}' "$(compose ps -q api)")
docker image inspect "$old_api_image" >/dev/null 2>&1 || { log 'Previous API image missing; rollback impossible'; exit 2; }
if docker image inspect "$NEW_API_IMAGE" >/dev/null 2>&1; then log 'Image tag already used'; exit 2; fi
stage=$(docker create "$old_api_image")
docker cp "$REL/src/packaging/guard/releases/$BUNDLE" "$stage:/app/guard-releases/$BUNDLE" >/dev/null
docker commit "$stage" "$NEW_API_IMAGE" >/dev/null
docker rm "$stage" >/dev/null
actual=$(docker run --rm --entrypoint sha256sum "$NEW_API_IMAGE" "/app/guard-releases/$BUNDLE" | awk '{print $1}')
[[ "$actual" == "$(cut -d' ' -f1 "$REL/src/packaging/guard/releases/$BUNDLE.sha256")" ]] || { log 'API image lost the reviewed Guard bundle; production untouched'; exit 2; }
log 'Guard bundle added to the running API image and verified'
cp -p "$APP_DIR/.env" "$REL/rollback/.env"; chmod 600 "$REL/rollback/.env"
printf 'previous_api_image=%s\nprevious_db_revision=%s\n' "$old_api_image" "$current_rev" >"$REL/rollback/previous-state.txt"
trap rollback ERR
staged="$APP_DIR/.env.guard-release-$RELEASE_ID"
cp -p "$APP_DIR/.env" "$staged"
sed -i -E "s#^ACCESSPROOF_API_IMAGE=.*#ACCESSPROOF_API_IMAGE=$NEW_API_IMAGE#; /^ACCESSPROOF_GUARD_RELEASE_VERSION=/d" "$staged"
printf 'ACCESSPROOF_GUARD_RELEASE_VERSION=%s\n' "$GUARD_VERSION" >>"$staged"
[[ "$(grep -c '^ACCESSPROOF_API_IMAGE=' "$staged")" == 1 ]] || { log 'API image env var missing'; false; }
mv "$staged" "$APP_DIR/.env"
compose up -d --no-deps --force-recreate api >"$REL/logs/api-deploy.log" 2>&1
wait_api
reload_nginx >>"$REL/logs/api-deploy.log" 2>&1
[[ "$(docker inspect -f '{{.Config.Image}}' "$(compose ps -q api)")" == "$NEW_API_IMAGE" ]] || false
[[ "$(compose exec -T api printenv ACCESSPROOF_GUARD_RELEASE_VERSION | tr -d '[:space:]')" == "$GUARD_VERSION" ]] || { log 'API did not receive the Guard release version'; false; }
for service in db redis web worker nginx; do
  prev=$(grep "^$service=" "$REL/rollback/unmodified-service-ids.txt" | cut -d= -f2)
  [[ "$prev" == "$(compose ps -q "$service")" ]] || { log "Unexpected container change: $service"; false; }
done
[[ "$(public_status https://api.accessproof.in/health/ready)" == 200 ]] || { log 'Production API readiness changed'; false; }
[[ "$(public_status https://api.accessproof.in/api/v1/guards/download)" == 401 ]] || { log 'Guard download is not authenticated'; false; }
[[ "$(public_status https://app.accessproof.in/login)" == 200 ]] || { log 'Public login unhealthy'; false; }
[[ "$(db_revision)" == "$current_rev" ]] || { log 'DB version changed unexpectedly'; false; }
trap - ERR
log "GUARD BUNDLE RELEASE VERIFIED $RELEASE_ID: Guard $GUARD_VERSION published, only api recreated"
