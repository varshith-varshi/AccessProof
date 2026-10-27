"""Opt-in synthetic Docker-only end-to-end reference RAG revocation test.

Creates disposable containers, no cloud account changes, no production data.
Requires a local Docker daemon, free loopback port 18220 and built reference RAG
image.  It is deliberately separate from normal pytest/production activation.
"""
from __future__ import annotations

import base64
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from packages.demo_cache.trusted_snapshot import write_snapshot
from packages.rag_core import (
    ContentBinding, RetrievedResource, SourceAttestationSigner,
)

IMAGE = "accessproof-drive-rag-audit:local"


def command(*args: str) -> None:
    subprocess.run(["docker", *args], check=True, stdout=subprocess.DEVNULL, timeout=90)


def run_smoke() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="accessproof-signed-smoke-"))
    marker = secrets.token_hex(5)
    network = f"ap-signed-smoke-{marker}"
    redis_name = f"ap-signed-redis-{marker}"
    backend_name = os.getenv("ACCESSPROOF_SMOKE_CACHE_BACKEND", "redis").lower()
    if backend_name not in {"redis", "memcached", "postgresql"}:
        raise ValueError("UNSUPPORTED_SMOKE_CACHE_BACKEND")
    guard_name = f"ap-signed-guard-{marker}"
    rag_name = f"ap-signed-rag-{marker}"
    items = [rag_name, guard_name, redis_name]
    try:
        command("network", "create", network)
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        cached_private = Ed25519PrivateKey.generate()
        cached_bytes = cached_private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        content = "Synthetic customer-only Q4 report 2026"
        binding = ContentBinding(
            "tenant-smoke", "app-smoke", "source-smoke", "file-smoke",
            "file-smoke:c0", "1", content,
        )
        doc = RetrievedResource(
            source_id=binding.source_id, resource_id=binding.resource_id,
            chunk_id=binding.chunk_id, content=binding.content,
            content_version=binding.content_version,
            content_attestation=SourceAttestationSigner(
                key_id="customer-ingester", private_key=private,
            ).issue(binding),
        )
        snapshot = tmp / "snapshot.json"
        write_snapshot(snapshot, tenant_id=binding.tenant_id,
                       application_id=binding.application_id,
                       source_id=binding.source_id, resources=[doc])
        state = tmp / "authorization.txt"
        state.write_text("allow")
        stub = tmp / "mock_guard.py"
        stub.write_text('''
from pathlib import Path
from fastapi import FastAPI, Request
app = FastAPI()
@app.get("/health")
def health(): return {"status":"ok","ready":True}
@app.post("/guard/v1/filter-resources")
async def filter_resources(req: Request):
    payload = await req.json()
    allowed = Path("/synthetic/authorization.txt").read_text().strip() == "allow"
    return {"decision_id":"synthetic-guard-id","mode":"protect",
            "decision":"allow" if allowed else "block",
            "allowed":payload["resources"] if allowed else []}
@app.post("/guard/v1/check-output")
async def check_output(req: Request):
    allowed = Path("/synthetic/authorization.txt").read_text().strip() == "allow"
    return {"decision":"allow" if allowed else "block",
            "reason":"SYNTHETIC_ORACLE"}
''')
        cache_env: list[str] = []
        if backend_name == "redis":
            command("run", "--rm", "-d", "--name", redis_name, "--network", network,
                    "--network-alias", "redis-synthetic", "redis:7-alpine")
            cache_env = [
                "-e", "ACCESSPROOF_DEMO_CACHE_URL=redis://redis-synthetic:6379/0",
            ]
        elif backend_name == "memcached":
            command("run", "--rm", "-d", "--name", redis_name, "--network", network,
                    "--network-alias", "memcached-synthetic", "memcached:1.6-alpine",
                    "-m", "32", "-I", "2m")
            cache_env = [
                "-e", "ACCESSPROOF_DEMO_CACHE_BACKEND=memcached",
                "-e", "ACCESSPROOF_DEMO_CACHE_MEMCACHED_HOST=memcached-synthetic",
            ]
        else:
            command("run", "--rm", "-d", "--name", redis_name, "--network", network,
                    "--network-alias", "postgres-synthetic",
                    "-e", "POSTGRES_PASSWORD=synthetic",
                    "-e", "POSTGRES_USER=synthetic",
                    "-e", "POSTGRES_DB=synthetic",
                    "postgres:17-alpine")
            for _ in range(50):
                ready = subprocess.run([
                    "docker", "exec", redis_name, "psql",
                    "-U", "synthetic", "-d", "synthetic",
                    "-tAc", "SELECT 1",
                ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if ready.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError("PostgreSQL did not become ready")
            # A dedicated customer-owned DB must have its cache table
            # provisioned explicitly, never implicitly on an employee GET.
            subprocess.run([
                "docker", "exec", redis_name, "psql", "-U", "synthetic",
                "-d", "synthetic", "-c",
                "CREATE TABLE accessproof_signed_cache_v1 ("
                "cache_key VARCHAR(240) PRIMARY KEY,"
                "value BYTEA NOT NULL,"
                "expires_at TIMESTAMPTZ NOT NULL);",
            ], check=True, stdout=subprocess.DEVNULL, timeout=15)
            cache_env = [
                "-e", "ACCESSPROOF_DEMO_CACHE_BACKEND=postgresql",
                "-e", ("ACCESSPROOF_DEMO_CACHE_SQLALCHEMY_URL="
                       "postgresql+psycopg://synthetic:synthetic@postgres-synthetic:5432/synthetic"),
            ]
        command("run", "--rm", "-d", "--name", guard_name, "--network", network,
                "--network-alias", "guard-synthetic",
                "-v", f"{stub}:/synthetic/mock_guard.py:ro",
                "-v", f"{state}:/synthetic/authorization.txt:ro",
                "--workdir", "/synthetic", IMAGE, "uvicorn", "mock_guard:app",
                "--host", "0.0.0.0", "--port", "18080")
        command("run", "--rm", "-d", "--name", rag_name, "--network", network,
                "-p", "127.0.0.1:18220:8200",
                "-v", f"{snapshot}:/synthetic/snapshot.json:ro",
                "-e", "ACCESSPROOF_ENV=production",
                "-e", "ACCESSPROOF_DEMO_GUARD_URL=http://guard-synthetic:18080",
                "-e", "ACCESSPROOF_DEMO_SOURCE_ID=source-smoke",
                "-e", "ACCESSPROOF_DEMO_APPLICATION_ID=app-smoke",
                "-e", "ACCESSPROOF_DEMO_REQUIRE_ATTESTED_CONTENT=1",
                "-e", "ACCESSPROOF_DEMO_ATTESTATION_TENANT=tenant-smoke",
                "-e", "ACCESSPROOF_DEMO_ATTESTATION_KEY_ID=customer-ingester",
                "-e", "ACCESSPROOF_DEMO_ATTESTATION_PUBLIC_KEY_B64=" + base64.b64encode(public).decode(),
                "-e", "ACCESSPROOF_DEMO_TRUSTED_SNAPSHOT_PATH=/synthetic/snapshot.json",
                *cache_env,
                "-e", "ACCESSPROOF_DEMO_CACHE_KEY_ID=customer-cache",
                "-e", "ACCESSPROOF_DEMO_CACHE_PRIVATE_KEY_B64=" + base64.b64encode(cached_bytes).decode(),
                IMAGE)
        with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
            for _ in range(75):
                try:
                    status = client.get("http://127.0.0.1:18220/health/ready")
                    if status.status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.2)
            else:
                raise AssertionError("Signed RAG readiness did not recover")
            payload = {"message": "What is in the authorized Q4 report?"}
            headers = {"Authorization": "Bearer synthetic-employee"}
            first = client.post("http://127.0.0.1:18220/v1/protected-chat",
                                json=payload, headers=headers)
            assert first.status_code == 200, first.text
            assert first.json()["cache_hit"] is False
            assert content in first.json()["answer"]
            cached = client.post("http://127.0.0.1:18220/v1/protected-chat",
                                 json=payload, headers=headers)
            assert cached.status_code == 200, cached.text
            assert cached.json()["cache_hit"] is True
            state.write_text("deny")
            revoked = client.post("http://127.0.0.1:18220/v1/protected-chat",
                                  json=payload, headers=headers)
            assert revoked.status_code == 403, revoked.text
            assert content not in revoked.text
            print("DOCKER_SIGNED_SOURCE_FIRST_ALLOW: PASS")
            print(f"DOCKER_{backend_name.upper()}_CACHE_HIT: PASS")
            print(f"DOCKER_{backend_name.upper()}_SAME_EMPLOYEE_REVOKED_DENIED: PASS")
    finally:
        for name in items:
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=25, check=False)
        subprocess.run(["docker", "network", "rm", network], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=25, check=False)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    run_smoke()
