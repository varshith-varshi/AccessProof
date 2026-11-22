#!/usr/bin/env bash
# Starts the API (http://localhost:8000) and the Vite dev server with hot reload
# (http://localhost:5173, proxies /api to the API). Ctrl+C stops both.
set -euo pipefail
cd "$(dirname "$0")"
[ -d .venv ] || { python3 -m venv .venv && ./.venv/bin/pip install -q -r requirements.txt; }
[ -d frontend/node_modules ] || (cd frontend && npm install --no-audit --no-fund)
./.venv/bin/uvicorn app.main:app --reload --port 8000 &
API=$!
trap 'kill $API 2>/dev/null' EXIT
cd frontend && npm run dev
