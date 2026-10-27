#!/usr/bin/env bash
set -euo pipefail
case "${1:-infra}" in
  infra) docker compose up -d db redis ;;
  full) docker compose --profile full up --build ;;
  down) docker compose --profile full --profile runner down ;;
  *) echo "Usage: $0 [infra|full|down]" >&2; exit 2 ;;
esac
