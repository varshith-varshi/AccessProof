#!/usr/bin/env bash
# Open the private localhost Alice/Bob validation page without exposing
# Microsoft credentials, bearer tokens or the one-time bootstrap secret.
set -euo pipefail
systemctl --user restart accessproof-human-validation-console.service
python3 - <<'PY'
from pathlib import Path
import subprocess
import time
import urllib.request
from urllib.error import HTTPError, URLError
import os
bootstrap = Path.home() / ".ap-id/validation-console-bootstrap"
for _ in range(30):
    try:
        with urllib.request.urlopen("http://127.0.0.1:28290/", timeout=1):
            pass
    except HTTPError as exc:
        if exc.code == 401 and bootstrap.is_file():
            break
    except (URLError, OSError):
        pass
    time.sleep(0.2)
else:
    raise SystemExit("LOCAL_VALIDATION_CONSOLE_NOT_READY")
# The server has generated a fresh, one-time bootstrap key. Never print it.
time.sleep(0.25)
secret = bootstrap.read_text().strip()
if len(secret) < 40:
    raise SystemExit("INVALID_OPERATOR_BOOTSTRAP")
url = "http://127.0.0.1:28290/?bootstrap=" + secret
subprocess.Popen(["xdg-open", url], stdin=subprocess.DEVNULL,
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                 start_new_session=True)
print("Opened the AccessProof secure Alice/Bob RAG page in your browser.")
print("Use 'Sign in with Microsoft' if either employee session has expired.")
PY
