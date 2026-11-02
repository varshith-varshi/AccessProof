# AccessProof multi-RAG discovery/planning foundation — engineering audit

Scope: repository branch `feature/real-customer-journey-r13`, following commits
`e9f3bfc` and `5026772`. This audit fixes customer-installer and
selection defects without changing production RAG routing or protection.

## Reproduced and fixed defects

1. **Downloaded ZIP missing dependencies:** The archive rebuild included
   `application_discovery.py` but omitted `selection_planner.py`.
   Moreover, the downloaded ZIP's main entrypoint did not accept
   `--discover`/`--plan`. The new repository commands were therefore
   unavailable through the actual customer download. The rebuilt archive now
   includes both modules and forwards these CLI options without pairing or
   installation. The matching `installer.py` and `existing_gateway.py`
   are bundled as well, avoiding stale mixed-generation Gateway code.
2. **Legacy stage regression:** The new `gateway_service` manifest field
   invalidated old default-service staged installations. Existing default
   `accessproof-gateway` receipts lacking that optional field now remain
   valid, while explicit non-default Gateway names still require a matching
   field. Reviewed deployment hash and private-file security checks remain.
3. **Bad discovery labels:** Bad/missing Compose route-environment metadata
   can no longer be advertised as supported. A forged integration label on a
   service with no valid Compose identity cannot qualify as supported.
4. **False-positive classification:** `storage` no longer matches the
   unbounded `rag` substring heuristic. This is diagnostic classification,
   NOT independent integration or production certification.
5. **Silently incomplete inventory:** More than 500 Docker inventory records
   now returns a clear discovery error rather than presenting a truncated
   machine scan as the whole inventory. Malformed direct input no longer
   suppresses valid later rows.
6. **Ambiguous selection:** Duplicate stable IDs and two selected runtime
   versions targeting the same Compose service now fail closed.
7. **Unsafe flag fallthrough:** Passing `--select` without `--plan` fails
   immediately instead of continuing to application pairing.

## Customer artifact tests

- Built a fresh installer ZIP from the previously downloaded official
  connector, preserving the pinned runtime archive, replacing changed Python
  modules only, and verifying the ZIP member list and CRC.
- The top-level `python3 connector.zip --discover` command completed on the
  authorized Ubuntu host without a pairing file.
- Live read-only inventory: 14 Docker service/container records; 2 classified
  supported RAGs, across separate Compose projects:
  `neuralmatrix-customer-rag-e2e/rag` and `sharepoint-rag-lab/rag`.
- `python3 connector.zip --plan --select ID --select ID` produced two
  distinct Gateway service names and loopback ports 18090 and 18091.
- New test exercises two separately staged Gateway overrides for
  Finance/HR against the real `docker compose config` CLI and verifies the
  unselected Sales RAG environment and source Compose bytes are unchanged.
- **No live Docker service was created, restarted, stopped or rerouted.**
  The plan and integration tests are non-mutating.

## Tests and quality

- Before fixes: original unit suite 626 passed; integration suite 152 passed,
  1 skipped. Explicitly disabled unrelated system ROS pytest plugin autoload
  and enabled `pytest_asyncio.plugin` for repeatable testing.
- After fixes: unit suite 643 passed; updated targeted feature tests 49 passed;
  new Docker Compose integration test passed.
- ESLint, TypeScript, Next.js production build, Playwright desktop/mobile:
  45 passed, 5 skipped.
- Ruff and Mypy of the new discovery/planning modules passed.
- Further security/contract/load test results must be recorded after completion.

## NOT implemented / NOT production-ready

This release is **only a safe local discovery/planning foundation**:
- No production host-enrollment API or machine-authenticated inventory sync.
- No durable host/application/installation-plan database migrations.
- No dashboard-backed app selection or approved installation execution loop.
- No production-safe port reservation, host-scoped identity, concurrent
  installation lock, or full multi-host identity handling.
- No end-to-end customer agent that installs multiple selected Gateways.
- No automatic source/Guard certification for newly discovered chatbots.
- Existing production SharePoint Protect remains subject to current backend
  fail-closed readiness checks.

The generated plan is advisory and has **not reserved those ports**; they
must be rechecked when an authorized installation is performed.

Do not deploy this partial foundation to production or label it complete.
Complete authenticated enrollment, durable inventory, approval and real
installation tests separately before production launch.

## Final audit additions

- Optional cache-security tests require `pymemcache>=4,<5`. The initial
  security/contract/load suite had 470 passes and 2 failures solely because
  this optional dependency was missing from this worktree's virtualenv.
  Installing the already-declared `cache-connectors` dependency resolved
  those failures: the affected cache test module passed all 24 tests. The
  package is now included in the project's `dev` extra for reproducible
  full security test installations. No cache enforcement was loosened.
- A previously ineffective symlink check on the ZIP entrypoint was repaired:
  callers cannot bypass the path check by resolving the link before asking
  whether it is a symlink. Added a dedicated regression test.
- Final reviewed local installer:
  `/tmp/accessproof-multirag-audit/accessproof-gateway-connector-multirag-reviewed.zip`.
  SHA-256 `330b9690a9207dd18520cb93c8d04205de42c49f0b19a61c8236e94cf8501333`
  (97,937,735 bytes). Real `--discover` and selected `--plan` both completed
  successfully with this ZIP and without a customer pairing key.
- One class of remaining test environment error is from globally installed
  ROS `launch_testing_ros_pytest_entrypoint` hooks leaking into the Python
  test virtualenv. The reliable isolated invocation is:
  `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -p pytest_asyncio.plugin ...`.
  The override is isolated to the test process and does not affect runtime.

## Completed final test matrix

- **Unit suite:** 643 passed, 0 failed.
- **Existing integration suite:** 152 passed, 1 skipped, 0 failed.
- **Security + contract + load suites:** 472 passed, 0 failed, after
  adding the declared optional `pymemcache` test dependency.
- **New real Docker Compose multi-Gateway configuration test:** 1 passed.
- **Website:** Next.js production build, ESLint and TypeScript passed;
  Playwright desktop/mobile 45 passed, 5 skipped.
- **Final zip safety regressions:** 10 passed, including symlink rejection.
- **Real customer-style CLI smoke:** official-runtime-preserving ZIP
  `--discover` and two selected `--plan` executed successfully against
  an actual Ubuntu Docker environment. No real production installation.
- **Code quality:** Ruff on modified modules and tests; Mypy on discovery
  and selection modules passed.
- **Git:** two audit commits after the original discovery/planning foundation,
  with clean working tree after the final evidence update.
- **Local reviewed installer copy:**
  `/home/white-devil/Downloads/accessproof-customer-lab/accessproof-gateway-connector-multi-rag-reviewed-20261102.zip`;
  SHA-256 `330b9690a9207dd18520cb93c8d04205de42c49f0b19a61c8236e94cf8501333`.
  This is a **local candidate installer**, not a production-certified
  release or a new production onboarding mechanism.
