# AccessProof — local adversarial security hardening (26 October 2026)

**Repository:** `/home/white-devil/Downloads/accessproof/f15`
**Scope:** Local source inspection, synthetic exploit reproduction, surgical code changes, and regression tests.
**Production:** NOT accessed or modified. No real customer tenant or credentials used. Existing Git working-tree edits preserved.
**Disposition:** Local Docker Compose certification bypass fixed; independent production/security validation still REQUIRED.

## Confirmed finding — AP-LOCAL-001 (HIGH)

The static `verify_reference_compose_isolation()` verifier previously accepted a Compose stack containing a RAG-accessible sidecar with a bind-mounted Docker daemon socket. Reproduced with `relay: {networks: [rag-isolated], volumes: [/var/run/docker.sock:/control.sock]}`; the function incorrectly returned `static_egress_isolated: true`. A container able to control the Docker daemon can create a network-attached relay outside the declared static Compose graph, making this certification false. **This is a validator bypass, not an observed end-user data leak.**

### Remediation

- Inspect short- and long-form mounts for Docker/containerd socket, host root and sensitive host runtime directories.
- Reject Docker daemon/host-control mounts across **every inspected Compose service**, including nominally unrelated services (which could dynamically rewire networks).
- Reject `volumes_from` in the inspected Compose stack; inherited mounts can evade a local mount declaration review.
- Reject explicitly unconfined security profiles on RAG-reachable sidecars in addition to existing checks for privileged, added-capability, host-network and multi-hop relays.
- Preserve a restricted, benign internal telemetry sidecar and unrelated public service when neither has host-control access.

**Changed files:** `apps/gateway/accessproof_gateway/network_boundary.py`; `tests/unit/test_gateway_network_boundary.py`.

### Verification

- Explicit positive exploit before fix: `SIDE_CAR_DOCKER_SOCKET_ACCEPTED=True`.
- Reproduction + rejection regression tests: Docker socket short mount, long bind, containerd socket, host-root mount, `volumes_from`, unrelated network service with socket, unconfined reachable sidecar and safe peers.
- Targeted network tests: **passed** (exit 0, 56 tests after final patch).
- Targeted Gateway authorization/cache/Guard test group: **passed** (exit 0, 67 tests at first fix checkpoint).
- Full `tests/security`: **377 passed** (exit 0) with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `-p pytest_asyncio.plugin` and `-o asyncio_mode=auto`. Initial failed invocation used the wrong async-plugin loading configuration; those were harness failures, not identified security bypasses.
- Full `tests/unit tests/integration`: **482 unit + 130 integration passed** (exit 0). Evidence `/tmp/accessproof_units_integration_hardened_20261026.log` (runtime ~393 seconds).
- Synthetic `tests/load/test_twin_large_policy_cache.py`: **1 passed** (exit 0). Fixture contains 10,000 resources and 24,000 concurrent decision lookups. Evidence `/tmp/accessproof_load_hardened_20261026.log`.
- In total **990 Python tests** passed across these suites and the final network additions were also rerun separately.
- Web v2 `npm run typecheck`, `npm run lint` and `npm run build`: **passed** (exit 0). Build produced the Next.js production route bundle, without deploying it.
- Web v2 Playwright E2E: **31 passed, 5 skipped** across desktop/mobile (exit 0). Mocked local API, not a real enterprise workspace. Evidence `/tmp/accessproof_web_e2e_20261026.log`.
- Ruff check + `git diff --check` for changed modules: **passed** (exit 0).

## Limits / remaining enterprise release blockers

1. **Live Google Workspace validation:** actual Drive resource IDs, nested groups, inheritance, shared drives, link grants, provider errors, and revoke behavior are not certified by mocks.
2. **Revocation latency and races:** measure provider change to Guard denial with percentile timings, missed events, cache expiry, reindexing during revocation, and stale directory/policy snapshots. Never claim instantaneous denial.
3. **Complete customer traffic interception:** certify each employee RAG route, model outbound path, cache, tool/agent path, alternate LLM endpoint and host firewall. Static Compose topology is only one prerequisite; production egress controls remain mandatory.
4. **Prompt injection and model claims:** cryptographic source attestations prove source bytes and authorization context, not factuality or guaranteed model obedience. No claim of preventing all hallucinations or leaks from model memory.
5. **Operational assurance:** staging load/soak, alerting, backup/restore, secret rotation, independent pentest, rollout/rollback and customer design-partner testing.

## Safe rerun commands

From repository root, using local disposable fixtures only:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q tests/unit/test_gateway_network_boundary.py -p pytest_asyncio.plugin -o asyncio_mode=auto --tb=short
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q tests/security -p pytest_asyncio.plugin -o asyncio_mode=auto --tb=short
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q tests/unit tests/integration -p pytest_asyncio.plugin -o asyncio_mode=auto --tb=short
.venv/bin/python -m ruff check apps/gateway/accessproof_gateway/network_boundary.py tests/unit/test_gateway_network_boundary.py
```

**Conservative final assessment:** Local bypass fixed and locally retested; do not label AccessProof production-ready or universally bypass-proof without live provider and customer boundary evidence.
