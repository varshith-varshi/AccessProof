from __future__ import annotations
from collections.abc import Awaitable, Callable
from packages.connector_sdk.base import SourceAdapter
from packages.connector_sdk.target import AITargetAdapter

from typing import Any, cast

import asyncio
import argparse
import json
import os
import signal
import socket
from pathlib import Path
import httpx

from packages.connector_sdk.http_target import GenericHttpTarget, HttpTargetConfig
from packages.domain.models import Principal
from packages.domain.scenario import ScenarioDefinition
from packages.reporting.report import build_manifest
from packages.test_engine.clock import Clock, SimulatedClock
from packages.test_engine.engine import EngineInterrupted, PermissionRegressionEngine
from packages.test_engine.probes import OpenAICompatibleProbeGenerator
from connectors.mock_source.adapter import MockSourceAdapter
from connectors.factory import create_source_adapter
from connectors.mock_source.target import MockRagTarget
from packages.observability.tracing import configure_tracing
from apps.runner.accessproof_runner.config import capabilities, host_platform, load_credentials
from apps.runner.accessproof_runner.enrollment import enroll, launch_enrollment_ui

API_URL = os.getenv("ACCESSPROOF_API_URL", "http://127.0.0.1:8000").rstrip("/")
RUNNER_ID = os.getenv("ACCESSPROOF_RUNNER_ID")
RUNNER_SECRET = os.getenv("ACCESSPROOF_RUNNER_SECRET")
POLL_SECONDS = float(os.getenv("RUNNER_POLL_SECONDS", "2"))
STATE_DIR = Path(os.getenv("ACCESSPROOF_RUNNER_STATE_DIR", ".accessproof-runner"))
VERSION = "0.9.0-pilot"


def _checkpoint_safe_job(job: dict[str, Any]) -> dict[str, Any]:
    """A leased job may contain short-lived caller tokens; never persist them locally."""
    safe = json.loads(json.dumps(job))
    for key in ("allowed_principal", "denied_principal"):
        if isinstance(safe.get(key), dict):
            safe[key].pop("access_token", None)
    return cast(dict[str, Any], safe)


def build_source(job: dict[str, Any], clock: Clock) -> SourceAdapter:
    src = job.get("source")
    if not src:
        return MockSourceAdapter(clock=clock)
    return create_source_adapter(src["provider"], dict(src.get("credentials") or {}), clock=clock)


def build_target(job: dict[str, Any], source: SourceAdapter, clock: Clock) -> AITargetAdapter:
    target = job.get("target")
    if not target:
        if not isinstance(source, MockSourceAdapter):
            raise ValueError("A real source requires an explicit AI target")
        return MockRagTarget(source=source, clock=clock, stale_acl_seconds=90)
    config = dict(target.get("config") or {})
    creds = target.get("credentials") or {}
    http_config = HttpTargetConfig(
        url=target["url"],
        method=config.get("method", "POST"),
        request_body=config.get(
            "request_body", {"message": "{{ probe }}", "user_id": "{{ principal.external_id }}"}
        ),
        static_headers=config.get("static_headers", {}),
        bearer_token=creds.get("bearer_token"),
        api_key_header=creds.get("api_key_header"),
        api_key_value=creds.get("api_key_value"),
        basic_username=creds.get("basic_username"),
        basic_password=creds.get("basic_password"),
        oauth_token_url=config.get("oauth_token_url") or creds.get("oauth_token_url"),
        oauth_client_id=creds.get("oauth_client_id"),
        oauth_client_secret=creds.get("oauth_client_secret"),
        oauth_scope=config.get("oauth_scope") or creds.get("oauth_scope"),
        mtls_cert_file=config.get("mtls_cert_file"),
        mtls_key_file=config.get("mtls_key_file"),
        mtls_ca_file=config.get("mtls_ca_file"),
        answer_path=config.get("answer_path", "answer"),
        citations_path=config.get("citations_path", "citations"),
        retrieved_documents_path=config.get("retrieved_documents_path", "retrieved_documents"),
        tool_outputs_path=config.get("tool_outputs_path", "tool_outputs"),
        runner_mode=True,
        timeout_seconds=float(config.get("timeout_seconds", 30)),
        session_strategy=str(config.get("session_strategy", "STATELESS")),
        session_create_url=config.get("session_create_url"),
        session_create_body=config.get("session_create_body", {}),
        session_id_path=config.get("session_id_path"),
    )
    return GenericHttpTarget(http_config)


async def execute_job(
    job: dict[str, Any],
    cancel_check: Callable[[], bool | Awaitable[bool]] | None = None,
    checkpoint_callback: Callable[[dict[str, Any]], None | Awaitable[None]] | None = None,
) -> dict[str, Any]:
    if job.get("type") != "permission_regression_v1":
        raise ValueError("Unsupported strongly-typed runner job")
    clock = SimulatedClock() if not job.get("source") and not job.get("target") else Clock()
    source = build_source(job, clock)
    target = build_target(job, source, clock)
    scenario = ScenarioDefinition.model_validate(job["scenario"])
    target_for_probes = job.get("target") or {}
    probe_config = target_for_probes.get("config") or {}
    # Target-level BYOK configuration is an explicit product opt-in.  It enables
    # additional questions while retaining the suite's deterministic oracle.
    if probe_config.get("probe_llm_endpoint") and not scenario.llm_probes.enabled:
        scenario = scenario.model_copy(update={"llm_probes": scenario.llm_probes.model_copy(update={"enabled": True})})
    probe_generator = None
    if scenario.llm_probes.enabled:
        # Prefer the encrypted target-level configuration supplied in the lease.
        # Environment variables remain a supported local-development fallback.
        probe_credentials = target_for_probes.get("credentials") or {}
        endpoint = probe_config.get("probe_llm_endpoint") or os.getenv("ACCESSPROOF_PROBE_LLM_ENDPOINT")
        api_key = probe_credentials.get("probe_llm_api_key") or os.getenv("ACCESSPROOF_PROBE_LLM_API_KEY")
        model = probe_config.get("probe_llm_model") or os.getenv("ACCESSPROOF_PROBE_LLM_MODEL")
        if endpoint and api_key and model:
            probe_generator = OpenAICompatibleProbeGenerator(
                endpoint=endpoint,
                api_key=api_key,
                model=model,
                provider=str(probe_config.get("probe_llm_provider") or os.getenv("ACCESSPROOF_PROBE_LLM_PROVIDER") or "openai-compatible"),
                version=probe_config.get("probe_llm_version") or os.getenv("ACCESSPROOF_PROBE_LLM_VERSION"),
                input_cost_per_million_tokens=float(
                    os.getenv("ACCESSPROOF_PROBE_LLM_INPUT_COST_PER_MILLION", "0")
                ),
                output_cost_per_million_tokens=float(
                    os.getenv("ACCESSPROOF_PROBE_LLM_OUTPUT_COST_PER_MILLION", "0")
                ),
                timeout_seconds=float(probe_config.get("probe_llm_timeout_seconds") or os.getenv("ACCESSPROOF_PROBE_LLM_TIMEOUT_SECONDS") or "30"),
            )
    engine = PermissionRegressionEngine(
        source,
        target,
        clock=clock,
        cancel_check=cancel_check,
        checkpoint_callback=checkpoint_callback,
        probe_generator=probe_generator,
    )
    allowed = Principal(**job["allowed_principal"])
    denied = Principal(**job["denied_principal"])
    result = await engine.run_revocation(
        allowed=allowed,
        denied_control=denied,
        scenario=scenario,
        resume_checkpoint=job.get("checkpoint"),
        run_id_override=job.get("run_id"),
        oracle_canary=job.get("oracle_canary"),
    )
    return dict(build_manifest(result)["payload"])


async def runner_loop() -> None:
    configure_tracing("accessproof-runner")
    stored = load_credentials()
    api_url = stored.api_url if stored else API_URL
    runner_id = stored.runner_id if stored else RUNNER_ID
    runner_secret = stored.runner_secret if stored else RUNNER_SECRET
    version = stored.version if stored else VERSION
    if not runner_id or not runner_secret:
        raise SystemExit("Runner is not enrolled. Open AccessProof Runner and enter an enrollment code.")
    platform_name, architecture = host_platform()
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    async with httpx.AsyncClient(timeout=35) as client:
        auth_headers = {"Authorization": f"Bearer {runner_secret}"}
        while not stop.is_set():
            try:
                heartbeat = await client.post(
                    f"{api_url}/api/v1/runners/heartbeat",
                    json={
                        "runner_id": runner_id,
                        "version": version,
                        "platform": platform_name,
                        "architecture": architecture,
                        "capabilities": capabilities(),
                    },
                    headers=auth_headers,
                )
                # Do not silently retry a credential that the control plane has
                # explicitly rejected. A stale local enrollment (for example
                # after restoring a database backup) otherwise creates an
                # endless 401 loop and looks like an unavailable runner. Keep
                # the credential file for diagnosis, but stop with a clear
                # operator action instead.
                if heartbeat.status_code in {401, 403}:
                    raise SystemExit(
                        "Runner credentials were rejected by AccessProof. "
                        "Create a new enrollment code and re-enroll this runner."
                    )
                heartbeat.raise_for_status()
                leased = await client.post(
                    f"{api_url}/api/v1/runners/lease",
                    json={"runner_id": runner_id},
                    headers=auth_headers,
                )
                leased.raise_for_status()
                job = leased.json().get("job")
                if not job:
                    await asyncio.sleep(POLL_SECONDS)
                    continue
                checkpoint = STATE_DIR / f"{job['run_id']}.json"
                checkpoint.write_text(
                    json.dumps({"job": _checkpoint_safe_job(job), "phase": "leased"}, sort_keys=True)
                )
                try:

                    async def cancel_check() -> bool:
                        try:
                            r = await client.get(
                                f"{api_url}/api/v1/runners/runs/{job['run_id']}/cancel-status",
                                params={"runner_id": runner_id},
                                headers=auth_headers,
                            )
                            return r.status_code == 200 and bool(r.json().get("cancel_requested"))
                        except httpx.HTTPError:
                            return False

                    async def checkpoint_callback(payload: dict[str, Any]) -> None:
                        checkpoint.write_text(json.dumps(payload, sort_keys=True))
                        try:
                            persisted = await client.post(
                                f"{api_url}/api/v1/runners/checkpoint",
                                json={
                                    "runner_id": runner_id,
                                    "run_id": job["run_id"],
                                    "checkpoint": payload,
                                },
                                headers=auth_headers,
                            )
                            persisted.raise_for_status()
                        except httpx.HTTPError as exc:
                            raise EngineInterrupted(
                                f"checkpoint persistence failed: {exc}"
                            ) from exc

                    result = await execute_job(
                        job, cancel_check=cancel_check, checkpoint_callback=checkpoint_callback
                    )
                except EngineInterrupted:
                    # Leave the lease/checkpoint for safe expiry and recovery. Do not submit a false terminal result.
                    await asyncio.sleep(POLL_SECONDS)
                    continue
                except Exception as exc:
                    result = {
                        "run_id": job["run_id"],
                        "outcome": "ERROR",
                        "reason": f"runner execution error: {type(exc).__name__}: {exc}",
                    }
                completed = await client.post(
                    f"{api_url}/api/v1/runners/complete",
                    json={
                        "runner_id": runner_id,
                        "run_id": job["run_id"],
                        "result": result,
                    },
                    headers=auth_headers,
                )
                completed.raise_for_status()
                checkpoint.unlink(missing_ok=True)
            except httpx.HTTPError:
                await asyncio.sleep(min(30, POLL_SECONDS * 3))


def main() -> None:
    parser = argparse.ArgumentParser(prog="accessproof-runner")
    subparsers = parser.add_subparsers(dest="command")
    enrollment = subparsers.add_parser("enroll", help="Connect this machine using an AccessProof enrollment code")
    enrollment.add_argument("--server", required=True, help="AccessProof API URL")
    enrollment.add_argument("--code", required=True, help="One-time enrollment code")
    enrollment.add_argument("--name", default=socket.gethostname(), help="Runner name")
    subparsers.add_parser("enroll-ui", help="Open the local enrollment window")
    subparsers.add_parser("service", help="Run the enrolled background service")
    args = parser.parse_args()
    if args.command == "enroll":
        connected = enroll(api_url=args.server, enrollment_code=args.code, name=args.name, version=VERSION)
        print(f"Connected runner {connected.name} to {connected.api_url}")
        return
    if args.command == "enroll-ui":
        launch_enrollment_ui(VERSION)
        return
    asyncio.run(runner_loop())


if __name__ == "__main__":
    main()
