#!/usr/bin/env bash
# Start detached Alice/Bob sign-in sessions (tokens stay in each process's memory).
# Detached so they outlive the operator tool's 2-hour background limit.
# Logs (sign-in links, VERIFIED lines; never tokens) go to ~/.ap-id/<actor>.log (0600).
set -euo pipefail
cd "$(dirname "$0")/../.."
install -d -m 700 "$HOME/.ap-id"
for actor in alice bob; do
  pid_file="$HOME/.ap-id/$actor.pid"
  if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    echo "$actor session already running (pid $(cat "$pid_file"))"; continue
  fi
  : > "$HOME/.ap-id/$actor.log"; chmod 600 "$HOME/.ap-id/$actor.log"
  setsid nohup env -u PYTHONPATH .venv/bin/python -u scripts/live/employee_identity.py serve \
    --actor "$actor" --client-id 9d031e10-4bed-4ab9-a98d-3eef237c4a56 \
    --socket "$HOME/.ap-id/$actor.sock" --max-hours "${AP_SESSION_HOURS:-12}" --signin-timeout 1800 \
    >> "$HOME/.ap-id/$actor.log" 2>&1 < /dev/null &
  echo $! > "$pid_file"
done
sleep 4
for actor in alice bob; do echo "== $actor"; grep -E 'https://login|VERIFIED|SERVING|IDENTITY_FAILURE' "$HOME/.ap-id/$actor.log" || true; done
