#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker Desktop or Docker Engine is required. Install Docker, then run this launcher again."
  exit 1
fi
if [ ! -f .env ]; then
  cp .env.example .env
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to check Guard startup. Install curl, then run again."
  exit 1
fi
# Docker Compose reads GUARD_PORT from .env, but does not export it to this
# shell. Read only the permitted numeric port instead of sourcing secrets.
port="${GUARD_PORT:-}"
if [ -z "$port" ]; then
  port="$(sed -n 's/^[[:space:]]*GUARD_PORT[[:space:]]*=[[:space:]]*//p' .env | tail -n 1 | tr -d '\r')"
  port="$(printf '%s' "$port" | sed -e 's/[[:space:]]*#.*$//' -e 's/[[:space:]]*$//')"
  port="${port#\"}"
  port="${port%\"}"
  port="${port#\'}"
  port="${port%\'}"
fi
port="${port:-8080}"
case "$port" in *[!0-9]*)
  echo "Invalid GUARD_PORT: use a numeric TCP port."
  exit 1
  ;;
esac
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
  echo "Invalid GUARD_PORT: use a port from 1 to 65535."
  exit 1
fi
mkdir -p state
docker compose -f compose.yml up -d --build guard
url="http://127.0.0.1:${port}/setup"
attempt=0
until curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo "Guard did not become ready. Run: docker compose -f compose.yml logs guard"
    exit 1
  fi
  sleep 1
done
if command -v xdg-open >/dev/null 2>&1; then xdg-open "$url" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then open "$url" || true
fi
echo "AccessProof Guard setup is open at $url"
