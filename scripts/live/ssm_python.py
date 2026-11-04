#!/usr/bin/env python3
"""Run python on a REMOTE RAG host through AWS SSM (used as --rag-exec for the certifier).

    ssm_python.py --instance i-... -c CODE   (stdin forwarded; prints the remote stdout)
Runs as root on the host so host probes (process environments) are observable.
"""
import argparse
import base64
import json
import subprocess
import sys
import time

p = argparse.ArgumentParser()
p.add_argument("--instance", required=True)
p.add_argument("--region", default="eu-north-1")
p.add_argument("-c", dest="code", required=True)
a = p.parse_args()
stdin = sys.stdin.read() if not sys.stdin.isatty() else ""
cmd = (f"echo {base64.b64encode(a.code.encode()).decode()} | base64 -d > /tmp/ap-probe.py && "
       f"echo {base64.b64encode(stdin.encode()).decode()} | base64 -d | /home/ubuntu/ap-remote-rag/venv/bin/python /tmp/ap-probe.py; "
       "rc=$?; rm -f /tmp/ap-probe.py; exit $rc")
cid = subprocess.run(["aws", "ssm", "send-command", "--region", a.region, "--instance-ids", a.instance,
                      "--document-name", "AWS-RunShellScript", "--comment", "remote route certification probe",
                      "--parameters", json.dumps({"commands": [cmd], "executionTimeout": ["300"]}),
                      "--query", "Command.CommandId", "--output", "text"], capture_output=True, text=True, check=True).stdout.strip()
while True:
    time.sleep(2)
    r = subprocess.run(["aws", "ssm", "get-command-invocation", "--region", a.region, "--command-id", cid,
                        "--instance-id", a.instance, "--output", "json"], capture_output=True, text=True)
    if r.returncode == 0:
        inv = json.loads(r.stdout)
        if inv["Status"] not in ("Pending", "InProgress", "Delayed"):
            sys.stdout.write(inv.get("StandardOutputContent", ""))
            sys.exit(0 if inv["Status"] == "Success" else 1)
