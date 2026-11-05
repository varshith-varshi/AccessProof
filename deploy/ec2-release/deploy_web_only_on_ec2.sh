#!/usr/bin/env bash
# AccessProof isolated web-only release via pinned SSM production document.
# Do not restart API, worker, Guard, DB, Redis or nginx, or run migrations.
# nginx is reloaded gracefully, never restarted: it resolves `web` only when its
# configuration loads, so a recreated web container on a new IP would otherwise
# serve 502. A reload keeps the same container and drains existing connections.
# The image is built off-host and arrives inside the checksummed artifact. Never
# run `docker build` here: on this 2 GB host a web build took down production on
# 2026-11-05 (see docs/INCIDENT_2026-11-05_WEB_BUILD_OUTAGE.md).
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
GATEWAY_SHA='bab5f15f62c5186235677e489d7020654e72600d1f999a83554fa160a5dd91d9'
SDK_SHA='ce72587503532202add008990e59fbf2a9c1c23e3740e1a4be3fac4b37235072'
SDK_FILE='accessproof_rag-0.1.0-py3-none-any.whl'
MIN_AVAILABLE_MB=300
INSTALLER_PATH=/app/public/downloads/accessproof-gateway-connector.zip
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
  # Each form must refuse a fabricated session, without transferring the file.
  local status url
  for url in downloads/accessproof-gateway-connector.zip "downloads/$SDK_FILE" downloads%2Faccessproof-gateway-connector.zip; do
    url="https://app.accessproof.in/$url"
    status=$(curl -sS -I -o /dev/null -w '%{http_code}' --max-time 18 \
      -H 'Cookie: accessproof_session=synthetic-invalid-no-real-session' "$url")
    [[ "$status" =~ ^(302|303|307|308|401|403)$ ]] || { log "Installer session check failed (HEAD $url): $status"; return 1; }
    status=$(curl -sS -r 0-0 -o /dev/null -w '%{http_code}' --max-time 18 \
      -H 'Cookie: accessproof_session=synthetic-invalid-no-real-session' "$url")
    [[ "$status" =~ ^(302|303|307|308|401|403)$ ]] || { log "Installer session check failed (GET $url): $status"; return 1; }
  done
}
public_status(){
  curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "$1" 2>/dev/null || true
}
rollback(){
  local code=$?
  trap - ERR
  log 'WEB RELEASE FAILED: restoring previous image and environment; other services were not targeted'
  if [[ -f "$REL/rollback/.env" ]]; then
    cp -p "$REL/rollback/.env" "$APP_DIR/.env"
    cp -p "$REL/rollback/docker-compose.ec2.yml" "$COMPOSE"
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
# Post-switch checks use the public hostnames. If they do not reach this service
# now (stale DNS, for example), refuse rather than deploy into a certain rollback.
[[ "$(public_status https://app.accessproof.in/login)" == 200 ]] || { log 'Public website unreachable before release; production untouched'; exit 2; }
[[ "$(public_status https://api.accessproof.in/health/ready)" == 200 ]] || { log 'Public API unreachable before release; production untouched'; exit 2; }
[[ "$(sha256sum "$ARCHIVE" | awk '{print $1}')" == "$EXPECTED_SHA" ]] || { log 'Archive checksum mismatch'; exit 2; }
[[ "$(tar -xOf "$ARCHIVE" RELEASE_COMMIT)" =~ ^[a-f0-9]{40}$ ]] || { log 'Missing commit identity'; exit 2; }
[[ ! -e "$REL/rollback/.env" ]] || { log 'This release ID was used before'; exit 2; }
free_gb=$(df -BG --output=avail / | tail -1 | tr -dc 0-9)
(( free_gb >= 8 )) || { log "Only ${free_gb}GB free; need 8GB"; exit 2; }
available_mb=$(awk '/^MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo)
log "Memory available: ${available_mb}MB"
(( available_mb >= MIN_AVAILABLE_MB )) || { log "Only ${available_mb}MB memory available; need ${MIN_AVAILABLE_MB}MB"; exit 2; }
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
[[ -f "$REL/src/web-image.tar.gz" && -f "$REL/src/web-image.digests" ]] || { log 'Prebuilt web image absent; on-host builds are not permitted'; exit 2; }
[[ -f "$REL/src/web-v2/public/downloads/$SDK_FILE" ]] || { log 'Reviewed SDK missing'; exit 2; }
[[ "$(sha256sum "$REL/src/web-v2/public/downloads/$SDK_FILE" | cut -d' ' -f1)" == "$SDK_SHA" ]] || { log 'Reviewed SDK checksum mismatch'; exit 2; }
old_web_image=$(docker inspect -f '{{.Config.Image}}' "$web_cid")
# Rollback depends on this image remaining on the host.
docker image inspect "$old_web_image" >/dev/null 2>&1 || { log 'Previous web image missing; rollback impossible'; exit 2; }
if docker image inspect "$NEW_WEB_IMAGE" >/dev/null 2>&1; then log 'Image tag already used'; exit 2; fi
# Decompression is the only local CPU work here, so `nice` applies to real load.
timeout --signal=TERM --kill-after=30s 10m nice -n 10 ionice -c2 -n7 gzip -dc "$REL/src/web-image.tar.gz" \
  | docker load >"$REL/logs/web-load.log" 2>&1 || { log 'Web image load failed or timed out; production untouched'; exit 2; }
loaded_id=$(docker image inspect -f '{{.Id}}' "$NEW_WEB_IMAGE" 2>/dev/null) || { log 'Loaded image has the wrong tag; production untouched'; exit 2; }
grep -Fxq "$loaded_id" "$REL/src/web-image.digests" || { log "Loaded image digest $loaded_id not approved; production untouched"; exit 2; }
[[ "$(docker image inspect -f '{{.Architecture}}' "$NEW_WEB_IMAGE")" == amd64 ]] || { log 'Web image is not amd64; production untouched'; exit 2; }
log "Web image loaded and verified: $loaded_id"
for expected in "$GATEWAY_SHA  /app/public/downloads/accessproof-gateway-connector.zip" "$SDK_SHA  /app/public/downloads/$SDK_FILE"; do
  actual=$(docker run --rm --entrypoint sha256sum "$NEW_WEB_IMAGE" "${expected#*  }" | awk '{print $1}')
  [[ "$actual" == "${expected%%  *}" ]] || { log 'Web image lost a reviewed customer download; production untouched'; exit 2; }
done
log 'Both published customer download artifacts verified in the new image'
cp -p "$APP_DIR/.env" "$REL/rollback/.env"; chmod 600 "$REL/rollback/.env"
cp -p "$COMPOSE" "$REL/rollback/docker-compose.ec2.yml"
# Production bind-mounts the installer over the image's copy, and that mount is
# not in the repository's Compose file. Point it at this release's verified ZIP,
# or a stale file keeps being served whatever the image contains.
installer_mount=$(docker inspect -f "{{range .Mounts}}{{if eq .Destination \"$INSTALLER_PATH\"}}{{.Type}} {{.Source}}{{end}}{{end}}" "$web_cid")
new_compose=""
if [[ -n "$installer_mount" ]]; then
  log "Installer is mounted over the image: $installer_mount"
  [[ "$installer_mount" == bind\ * ]] || { log 'Installer mount is not a bind mount; production untouched'; exit 2; }
  [[ "$(grep -c ":$INSTALLER_PATH" "$COMPOSE")" == 1 ]] || { log 'Installer mount line not found exactly once; production untouched'; exit 2; }
  install -d -m 755 "$REL/installer"
  stage=$(docker create "$NEW_WEB_IMAGE")
  docker cp "$stage:$INSTALLER_PATH" "$REL/installer/accessproof-gateway-connector.zip" >/dev/null
  docker rm "$stage" >/dev/null
  chmod 644 "$REL/installer/accessproof-gateway-connector.zip"
  [[ "$(sha256sum "$REL/installer/accessproof-gateway-connector.zip" | cut -d' ' -f1)" == "$GATEWAY_SHA" ]] || { log 'Extracted installer differs from approved digest; production untouched'; exit 2; }
  new_compose="$APP_DIR/.compose.web-release-$RELEASE_ID"
  cp -p "$COMPOSE" "$new_compose"
  sed -i -E "s#^([[:space:]]*-[[:space:]]*\"?)[^[:space:]\"]+:$INSTALLER_PATH#\1$REL/installer/accessproof-gateway-connector.zip:$INSTALLER_PATH#" "$new_compose"
  [[ "$(grep -c "^[[:space:]]*-[[:space:]]*\"\?$REL/installer/accessproof-gateway-connector.zip:$INSTALLER_PATH" "$new_compose")" == 1 ]] || { log 'Could not repoint installer mount; production untouched'; exit 2; }
fi
printf 'previous_web_image=%s\nprevious_db_revision=%s\n' "$old_web_image" "$current_rev" > "$REL/rollback/previous-state.txt"
log 'Previous image and .env saved; switching web only'
trap rollback ERR
staged="$APP_DIR/.env.web-release-$RELEASE_ID"
cp -p "$APP_DIR/.env" "$staged"
sed -i -E "s#^ACCESSPROOF_WEB_IMAGE=.*#ACCESSPROOF_WEB_IMAGE=$NEW_WEB_IMAGE#" "$staged"
[[ "$(grep -c '^ACCESSPROOF_WEB_IMAGE=' "$staged")" == 1 ]] || { log 'Web image env var missing'; false; }
mv "$staged" "$APP_DIR/.env"
[[ -z "$new_compose" ]] || mv "$new_compose" "$COMPOSE"
compose up -d --no-deps --force-recreate web >"$REL/logs/web-deploy.log" 2>&1
reload_nginx >>"$REL/logs/web-deploy.log" 2>&1
wait_web
new_web_cid=$(compose ps -q web)
[[ "$new_web_cid" != "$web_cid" ]] || { log 'Web container did not recreate'; false; }
# Check the running container: mounts can hide what the image contains.
for expected in "$GATEWAY_SHA  $INSTALLER_PATH" "$SDK_SHA  /app/public/downloads/$SDK_FILE"; do
  actual=$(compose exec -T web sha256sum "${expected#*  }" | awk '{print $1}')
  [[ "$actual" == "${expected%%  *}" ]] || { log "Running web serves the wrong file: ${expected#*  }"; false; }
done
[[ "$(docker inspect -f '{{.Config.Image}}' "$new_web_cid")" == "$NEW_WEB_IMAGE" ]] || false
for service in db redis api worker nginx; do
  prev=$(grep "^$service=" "$REL/rollback/unmodified-service-ids.txt" | cut -d= -f2)
  curr=$(compose ps -q "$service")
  [[ "$prev" == "$curr" ]] || { log "Unexpected container change: $service"; false; }
done
# Verify auth on actual production URL; invalid cookie must not release any ZIP.
installer_denied
[[ "$(public_status https://app.accessproof.in/login)" == 200 ]] || { log 'Public login unhealthy'; false; }
[[ "$(public_status https://api.accessproof.in/health/ready)" == 200 ]] || { log 'Production API readiness changed'; false; }
[[ "$(compose exec -T db psql -U accessproof -d accessproof -tAc 'select version_num from alembic_version' | tr -d '[:space:]')" == "$current_rev" ]] || { log 'DB version changed unexpectedly'; false; }
trap - ERR
log "WEB-ONLY RELEASE VERIFIED $RELEASE_ID: image $loaded_id, web healthy, previous API/worker/db/redis/nginx container IDs unchanged, installer authorization enforced"
