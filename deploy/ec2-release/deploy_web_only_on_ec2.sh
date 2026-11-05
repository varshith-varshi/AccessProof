#!/usr/bin/env bash
# AccessProof isolated web-only release via pinned SSM production document.
# Do not restart API, worker, Guard, DB, Redis or nginx, or run migrations.
# nginx is reloaded gracefully, never restarted: it resolves `web` only when its
# configuration loads, so a recreated web container on a new IP would otherwise
# serve 502. A reload keeps the same container and drains existing connections.
set -Eeuo pipefail
umask 077
RELEASE_ID="${1:?release id}"; ARCHIVE="${2:?release tar}"; EXPECTED_SHA="${3:?archive sha256}"
EXPECTED_DB_REVISION="${EXPECTED_DB_REVISION:?expected production database revision required}"
[[ "${PUBLIC_CHECKS:-1}" == 1 ]] || { echo 'Production release requires public checks' >&2; exit 2; }
[[ "$RELEASE_ID" =~ ^[a-z0-9][a-z0-9.-]{5,80}$ ]] || exit 2
[[ "$EXPECTED_DB_REVISION" =~ ^[a-z0-9]{12}$ && "$EXPECTED_SHA" =~ ^[a-f0-9]{64}$ ]] || exit 2
APP_DIR=/home/ubuntu/accessproof
COMPOSE="$APP_DIR/docker-compose.ec2.yml"
REL="/home/ubuntu/accessproof-releases/$RELEASE_ID"
NEW_WEB_IMAGE="accessproof/web-v2:$RELEASE_ID"
GATEWAY_SHA='91a7c7d421316e882fe15003c8023bc4cc50de88cef9c6913c98cb887ae3df9a'
SDK_SHA='ce72587503532202add008990e59fbf2a9c1c23e3740e1a4be3fac4b37235072'
SDK_FILE='accessproof_rag-0.1.0-py3-none-any.whl'
log(){ printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
compose(){ docker compose --project-directory "$APP_DIR" -f "$COMPOSE" "$@"; }
wait_web(){
  local cid state deadline=$((SECONDS + 180))
  while (( SECONDS < deadline )); do
    cid=$(compose ps -q web || true)
    if [[ -n "$cid" ]]; then
      state=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid")
      [[ "$state" == healthy ]] && return 0
    fi
    sleep 3
  done
  return 1
}
reload_nginx(){
  compose exec -T nginx nginx -t && compose exec -T nginx nginx -s reload
}
installer_denied(){
  # Each form must refuse a fabricated session, without transferring the ZIP.
  local status
  for form in head get; do
    if [[ "$form" == head ]]; then
      status=$(curl -sS -I -o /dev/null -w '%{http_code}' --max-time 18 \
        -H 'Cookie: accessproof_session=synthetic-invalid-no-real-session' \
        https://app.accessproof.in/downloads/accessproof-gateway-connector.zip)
    else
      status=$(curl -sS -r 0-0 -o /dev/null -w '%{http_code}' --max-time 18 \
        -H 'Cookie: accessproof_session=synthetic-invalid-no-real-session' \
        https://app.accessproof.in/downloads/accessproof-gateway-connector.zip)
    fi
    [[ "$status" =~ ^(302|303|307|308|401|403)$ ]] || { log "Installer session check failed ($form): $status"; return 1; }
  done
}
rollback(){
  local code=$?
  trap - ERR
  log 'WEB RELEASE FAILED: restoring previous image and environment; other services were not targeted'
  if [[ -f "$REL/rollback/.env" ]]; then
    cp -p "$REL/rollback/.env" "$APP_DIR/.env"
    if compose up -d --no-deps --force-recreate web >>"$REL/rollback/web-restore.log" 2>&1 \
      && reload_nginx >>"$REL/rollback/web-restore.log" 2>&1 && wait_web \
      && [[ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 https://app.accessproof.in/login)" == 200 ]]; then
      log 'WEB ROLLBACK VERIFIED: previous web image healthy'
    else
      log 'CRITICAL: WEB ROLLBACK NOT VERIFIED; immediate operator intervention required' >&2
    fi
  fi
  exit "${code:-1}"
}
install -d -m 700 /home/ubuntu/accessproof-releases
exec 9>>/home/ubuntu/accessproof-releases/.release.lock
flock -n 9 || { log 'Another release holds production release lock'; exit 75; }
install -d -m 700 "$REL" "$REL/src" "$REL/rollback" "$REL/logs"
log "Production isolated web release $RELEASE_ID starting"
[[ "$(sha256sum "$ARCHIVE" | awk '{print $1}')" == "$EXPECTED_SHA" ]] || { log 'Archive checksum mismatch'; exit 2; }
[[ "$(tar -xOf "$ARCHIVE" RELEASE_COMMIT)" =~ ^[a-f0-9]{40}$ ]] || { log 'Missing commit identity'; exit 2; }
[[ ! -e "$REL/rollback/.env" ]] || { log 'This release ID was used before'; exit 2; }
free_gb=$(df -BG --output=avail / | tail -1 | tr -dc 0-9)
(( free_gb >= 8 )) || { log "Only ${free_gb}GB free; need 8GB"; exit 2; }
current_rev=$(compose exec -T db psql -U accessproof -d accessproof -tAc 'select version_num from alembic_version' | tr -d '[:space:]')
[[ "$current_rev" == "$EXPECTED_DB_REVISION" ]] || { log 'Database revision changed since authorization'; exit 2; }
for service in db redis api web; do
  cid=$(compose ps -q "$service")
  [[ -n "$cid" ]] || { log "Missing $service container"; exit 2; }
  state=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid")
  [[ "$state" == healthy ]] || { log "$service not healthy ($state)"; exit 2; }
done
worker_cid=$(compose ps -q worker); [[ -n "$worker_cid" ]] || { log 'Missing worker'; exit 2; }
worker_state=$(docker inspect -f '{{.State.Status}}' "$worker_cid")
[[ "$worker_state" == running ]] || { log 'Worker not running'; exit 2; }
for service in db redis api worker nginx; do printf '%s=%s\n' "$service" "$(compose ps -q "$service")"; done >"$REL/rollback/unmodified-service-ids.txt"
web_cid=$(compose ps -q web)
[[ -n "$web_cid" ]] || exit 2
[[ ! -e "$REL/src/web-v2" ]] || { log 'Source already extracted'; exit 2; }
tar -xf "$ARCHIVE" -C "$REL/src"
[[ -f "$REL/src/web-v2/Dockerfile" ]] || { log 'Web build source absent'; exit 2; }
[[ -f "$REL/src/web-v2/public/downloads/$SDK_FILE" ]] || { log 'Reviewed SDK missing'; exit 2; }
[[ "$(sha256sum "$REL/src/web-v2/public/downloads/$SDK_FILE" | cut -d' ' -f1)" == "$SDK_SHA" ]] || { log 'Reviewed SDK checksum mismatch'; exit 2; }
[[ ! -e "$REL/src/web-v2/public/downloads/accessproof-gateway-connector.zip" ]] || { log 'Gateway ZIP must be inherited from currently published artifact'; exit 2; }
# The current public ZIP is not in Git. Preserve exactly the existing reviewed
# 97.9MB archive so a web-only update does not delete customer downloads.
docker cp "$web_cid:/app/public/downloads/accessproof-gateway-connector.zip" "$REL/src/web-v2/public/downloads/accessproof-gateway-connector.zip" >/dev/null
[[ "$(sha256sum "$REL/src/web-v2/public/downloads/accessproof-gateway-connector.zip" | cut -d' ' -f1)" == "$GATEWAY_SHA" ]] || { log 'Existing published Gateway ZIP differs from approved digest'; exit 2; }
python3 - "$REL/src/web-v2/public/downloads/accessproof-gateway-connector.zip" <<'PY'
import sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    assert {'__main__.py','accessproof-gateway-connector/accessproof-gateway-runtime.tar.gz'}.issubset(set(z.namelist()))
    assert z.testzip() is None
PY
log 'Both published customer download artifacts verified'
if docker image inspect "$NEW_WEB_IMAGE" >/dev/null 2>&1; then log 'Image tag already used'; exit 2; fi
# Build before changing live .env or containers. The production host also serves
# customer traffic, so explicitly yield CPU and disk scheduling priority to the
# running API, web, database, and proxy while Docker builds the replacement.
# `nice`/`ionice` affect the build client and the legacy builder descendants;
# existing service containers retain their normal scheduling priority. A build
# that cannot finish within the bounded window is terminated before any live
# configuration or container is changed.
timeout --signal=TERM --kill-after=30s 20m \
  nice -n 10 ionice -c2 -n7 docker build -t "$NEW_WEB_IMAGE" "$REL/src/web-v2" \
  >"$REL/logs/web-build.log" 2>&1 || { log 'Web build failed or timed out; production untouched'; exit 2; }
for expected in "$GATEWAY_SHA  /app/public/downloads/accessproof-gateway-connector.zip" "$SDK_SHA  /app/public/downloads/$SDK_FILE"; do
  actual=$(docker run --rm --entrypoint sha256sum "$NEW_WEB_IMAGE" "${expected#*  }" | awk '{print $1}')
  [[ "$actual" == "${expected%%  *}" ]] || { log 'Built web image lost a reviewed customer download'; exit 2; }
done
cp -p "$APP_DIR/.env" "$REL/rollback/.env"; chmod 600 "$REL/rollback/.env"
cp -p "$COMPOSE" "$REL/rollback/docker-compose.ec2.yml"
old_web_image=$(docker inspect -f '{{.Config.Image}}' "$web_cid")
printf 'previous_web_image=%s\nprevious_db_revision=%s\n' "$old_web_image" "$current_rev" > "$REL/rollback/previous-state.txt"
log 'Previous image and .env saved; switching web only'
trap rollback ERR
staged="$APP_DIR/.env.web-release-$RELEASE_ID"
cp -p "$APP_DIR/.env" "$staged"
sed -i -E "s#^ACCESSPROOF_WEB_IMAGE=.*#ACCESSPROOF_WEB_IMAGE=$NEW_WEB_IMAGE#" "$staged"
[[ "$(grep -c '^ACCESSPROOF_WEB_IMAGE=' "$staged")" == 1 ]] || { log 'Web image env var missing'; false; }
mv "$staged" "$APP_DIR/.env"
compose up -d --no-deps --force-recreate web >"$REL/logs/web-deploy.log" 2>&1
reload_nginx >>"$REL/logs/web-deploy.log" 2>&1
wait_web
new_web_cid=$(compose ps -q web)
[[ "$new_web_cid" != "$web_cid" ]] || { log 'Web container did not recreate'; false; }
[[ "$(docker inspect -f '{{.Config.Image}}' "$new_web_cid")" == "$NEW_WEB_IMAGE" ]] || false
for service in db redis api worker nginx; do
  prev=$(grep "^$service=" "$REL/rollback/unmodified-service-ids.txt" | cut -d= -f2)
  curr=$(compose ps -q "$service")
  [[ "$prev" == "$curr" ]] || { log "Unexpected container change: $service"; false; }
done
# Verify auth on actual production URL; invalid cookie must not release any ZIP.
installer_denied
login_status=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 https://app.accessproof.in/login)
[[ "$login_status" == 200 ]] || { log 'Public login unhealthy'; false; }
api_status=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 https://api.accessproof.in/health/ready)
[[ "$api_status" == 200 ]] || { log 'Production API readiness changed'; false; }
[[ "$(compose exec -T db psql -U accessproof -d accessproof -tAc 'select version_num from alembic_version' | tr -d '[:space:]')" == "$current_rev" ]] || { log 'DB version changed unexpectedly'; false; }
trap - ERR
log "WEB-ONLY RELEASE VERIFIED $RELEASE_ID: web healthy, previous API/worker/db/redis/nginx container IDs unchanged, installer authorization enforced"
