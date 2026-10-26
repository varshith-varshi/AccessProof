# AccessProof Gateway V1 — adversarial local security review

**Review date:** 26 October 2026
**Repository:** /home/white-devil/Downloads/accessproof/f15
**Production status:** **NO-GO pending independent enterprise validation.**
**Target:** Gateway-only Google Workspace / Google Drive authorization enforcement.

## Testing scope and safety

All attacks were synthetic, confined to offline Python mocks, disposable SQLite
databases, and loopback/local reference services. No real Google Workspace tenant,
customer RAG, company information, production endpoint, or real credential was
used. No live server was modified. Existing uncommitted source code and local
master were preserved; an isolated reviewed source snapshot is pushed to the
private draft PR.

Reviewed: Gateway input validation, signed retrieval provenance, Guard
Layer 1/Layer 2 release, production Guard revision and identity readiness,
authorization source binding, cache-manifest signatures and reauthorization,
stale policy/revocation paths, Docker reference topology certification, the
customer-agent installer and route-cutover tests, request/response size controls,
model provider adapters, redirect handling, and high-risk subprocess patterns.

## Findings fixed

### AP-RT-001 — transitive Docker network egress relay (HIGH)

**Reproduction:** Add a sidecar service to an otherwise trusted reference
Compose manifest with `networks: [rag-isolated, model-private]`.
Before remediation `verify_reference_compose_isolation(...)` returned
`static_egress_isolated: true`. Yet RAG could reach the sidecar on its network,
and that sidecar could contact the model on the model network. A multi-hop
chain (rag → relay1 → relay2 → model) also escaped the direct-network check.

**Remediation:** Build transitive reachability over every non-Gateway Compose
service. Fail certification if a service can connect RAG networks to a model
network or any non-internal network. Reject unreviewable relay peers with
published ports, privileged host networking, capabilities and devices. Preserve
legitimate isolated peers and unrelated services that cannot touch RAG.

**Regression:** `tests/unit/test_gateway_network_boundary.py` includes
single-hop/multi-hop sidecars, outward relay paths, cloud-native model bypass,
safe internal peers and unrelated public services.

### AP-RT-002 — hidden shared network namespace relay (HIGH)

**Reproduction:** A sidecar configured with `network_mode:
service:accessproof-gateway` or `network_mode: service:model` had no declared
`networks` edge and initially still passed static certification. A sidecar
sharing Gateway's network namespace could host an unprotected proxy while
remaining invisible to the old network-graph rule.

**Remediation:** Refuse all Compose `network_mode` namespace overrides
and shared host/container PID/IPC namespaces in the reviewed reference stack.
Tests cover service/container/host namespace variants.

### AP-RT-003 — elevated capabilities and host devices (MEDIUM-HIGH)

**Reproduction:** The reference verifier initially accepted a RAG service with
`cap_add: [NET_ADMIN]`, access to `/dev/net/tun`, or a Gateway that re-added
NET_ADMIN after `cap_drop: [ALL]`. Such privileges invalidate confidence that
the declared network topology cannot be changed or bypassed.

**Remediation:** Reject `cap_add`, host `devices` and explicitly
unconfined seccomp/AppArmor profiles for RAG and Gateway. Tests verify
standard no-new-privileges and cap-drop profiles still pass.

All three findings concern **incorrectly accepted deployment certification
conditions**. They are not evidence of an observed breach of employee
information. Final release must additionally test real customer traffic and
prohibit unprotected egress by infrastructure controls.

### AP-RT-004 — obsolete validation runner referenced deleted SDK suites (MEDIUM)

**Reproduction:** The synthetic enterprise validation runner selected four
historical SDK/framework test modules which no longer exist in the product
following the Gateway-only cutover. The stage could not execute, leaving a
false failure and a gap in the current Gateway release checks.

**Remediation:** Replace the obsolete stage with Gateway authorization,
signed-source, readiness, transport, network-isolation, late-source and
cache tests. Add an explicit startup check that every path in `CHECKS`
exists before running anything. The synthetic report now identifies the sole
supported customer integration as `accessproof-gateway`, never a framework SDK.

**Regression:** `tests/unit/test_customer_validation_runner_scope.py`.
The upgraded complete Gateway validation selection and the two runner-scope
tests passed **141 cases**. Evidence:
`/tmp/ap-redteam-gateway-validation-stage.log`.

This is a **test/release pipeline defect**, not an observed data disclosure.

## Previously implemented protections retested

- Source attestation signatures bind tenant, app, source, resource, chunk,
  content version, exact bytes, expiry and key ID. Tampered bytes are blocked
  before model generation in existing tests.
- Layer 1 excludes unauthorized chunks from LLM context; requests with no
  authorized source cannot continue to model execution.
- Layer 2 consumes authorization decision contexts with one-time usage and
  rechecks current permissions, installed revisions and app mode before release.
- Cached answers must have signed, complete source dependencies and
  reauthorization before reuse.
- The customer Gateway buffers output before returning content, including
  SSE; native unverified token streaming and tool calls are not certified.
- Public HTTP and special-use upstream addresses are refused. Gateway
  readiness is tied to the specific enrolled Protect application, current
  permissions and production authorization-revision / identity snapshots.
- Tests include tenant/resource ID mismatch, revoked/stale permissions,
  Guard outages, denied employees, shadow/protect downgrade, model and
  source tampering and known provenance edge cases.

## Evidence

| Test group | Status | Evidence |
| --- | --- | --- |
| Expanded network + installer + customer-agent + cutover | 90 passed | /tmp/ap-redteam-network-gates-expanded.log |
| Gateway-only customer validation stage + runner scope | 141 passed | /tmp/ap-redteam-gateway-validation-stage.log |
| Complete Python unit suite (before last runner-scope tests) | 462 passed | /tmp/ap-redteam-unit-suite.log |
| Complete Python security suite | 377 passed | /tmp/ap-redteam-security-suite.log |
| Complete Python integration suite | 130 passed | /tmp/ap-redteam-integration-suite.log |

Build verification: `accessproof-gateway:redteam-net-isolation-20261026` built from the patched files and runs as the nonroot `accessproof` user.
Static analysis: Ruff and mypy run on changed network-verifier code.
No direct shell=True / pickle.loads / TLS verify=False sites were observed in
the examined active Python gateway, Guard, packages and connector code via
basic grep. This is not a substitute for dependency scanning, SBOM or a
third-party penetration test.

## Unresolved release blockers — do not claim a certified universal Gateway

1. **Real Google Workspace semantics:** Validate stable identity mapping,
   membership nesting, shared drives, inherited folders, group revocation,
   links/domain grants, provider outages and cross-tenant denial against a real,
   authorized Workspace. Synthetic fixtures cannot establish correctness.
2. **Revocation SLO and concurrency:** Measure real Workspace permission-change
   to effective Guard denial, including p50/p95/p99, missed provider events,
   worker restarts, full reconciliation and stale policy.
3. **Customer RAG bypass surface:** This verifier detects several static
   Docker misconfigurations but cannot prove no bypass from uninspected
   application code, process compromise, Kubernetes, DNS rebinding, host
   firewall policy, hidden tool/cache paths, host-network escape, or a malicious
   already-running peer. Customer-owned egress policy plus real HTTP
   employee-route validation is mandatory.
4. **Provider and LLM behavior:** Prompt injection, memorized model content and
   unsourced generated claims cannot be proven safe solely with source-id
   lineage. Model provider terms/region, any model persistence, tool support,
   streaming, caches and any agent actions need route-by-route review.
5. **Operational production assurance:** Independent security audit, staging
   rollback/restore exercises, secret rotation, risk review, live alerting,
   incident response, concurrency/load testing and continuous hosted CI remain.
6. **PR hosting constraints:** The private draft PR is not automatically
   production-certified. GitHub Actions workflow upload had previously been
   blocked by missing `workflow` OAuth scope.

**Final disposition:** These locally confirmed bypasses were remediated and
covered with explicit regression tests. **No unrestricted enterprise launch**
is authorized by this report.
