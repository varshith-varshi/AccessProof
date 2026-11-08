# AccessProof local Human Validation — startup recovery reference

**Lab-only. Not an always-on customer deployment and not a certification issuer.**

This folder preserves the source used by the local SharePoint Human Validation
RAG. The live instance runs separately from
`~/Downloads/accessproof-human-validation-rag` on the approved Ubuntu test
host; the code here is not automatically deployed when the repository changes.
Do not copy private `.env`, private signing PEMs, employee OAuth sessions or
Gateway installer credentials into Git.

## Normal startup

Docker and Ollama start through their enabled system services. The customer
Guard, Gateway, RAG, Redis, ingester, and model bridge containers all use
`restart: unless-stopped`. The user has systemd lingering enabled, so the
`accessproof-local-ollama-bridge.service` starts even without a desktop login.

The `accessproof-human-validation-recovery.timer` starts after the user manager
boots and checks every two minutes. Its oneshot service can start only the
explicitly named **existing** containers. Missing installations are reported
rather than automatically reconstructed. If the signed index is stale or
invalid, the service may restart only the separate **trusted SharePoint
ingester**, with a four-minute cooldown. No Guard policy or authorization
fallback is ever enabled.

The recovery controller stores a mode-0600 JSON report at
`~/.config/accessproof/human-validation-recovery/latest.json`. To check
read-only health:

```bash
python3 ~/Downloads/accessproof-human-validation-rag/scripts/recover_lab.py --check
systemctl --user status accessproof-human-validation-recovery.timer
docker ps --format '{{.Names}} {{.Status}}'
curl --fail http://127.0.0.1:28189/health/ready
```

**Do not reboot the laptop for these checks without its owner's approval.**

## Signed-content readiness and isolation

An ingester with trusted Graph credentials, provider egress and the private
Ed25519 signing key periodically re-fetches synthetic SharePoint documents,
signs exact bytes and atomically replaces the index. The ingester Docker
healthcheck requires a recent sync. The RAG Docker healthcheck, its
`/health/ready` endpoint, and each protected question require all signed
index chunks to be fresh, signed by a pinned public key, and bound to the exact
tenant/source/application/item/version/bytes. No near-expiry tokens are
accepted. The Gateway independently performs the final signed-content,
Layer 1 and Layer 2 verification.

**The RAG must receive only public configuration**, in a mode-0600
`.env.rag` file: `LAB_TENANT_ID`, `LAB_APPLICATION_ID`, `LAB_SOURCE_ID`,
`LAB_ENABLE_BASELINE=0` and `LAB_SOURCE_PUBLIC_KEYS_JSON`. Its source
public key should be matched to the Gateway verifier and the trusted
ingester's signer before onboarding. The original `.env` file with
SharePoint Graph credentials belongs to the `ingest` service only.

All confidential test-document content remains in the private customer RAG
index; the Alice/Bob operator console uses memory-only real Microsoft Entra
sessions, no password or bearer token storage in the browser. After a
shutdown, each employee may need to sign in again.

The local Ollama model bridge is pinned to the known model and host-only
network path. Local endpoints do not themselves establish production
certification or continuous availability when the laptop is powered off.

## Installation constraints

The live installation has reviewed Guard/Gateway installer manifests and
separately provisioned source credentials. This reference deliberately omits
those assets. Reinstalling from this folder **requires** a new, authorized
customer onboarding and signed Gateway pairing. Never invent manifests,
keys, Microsoft identities or certificate evidence to make health green.
Use the installer for Guard/Gateway rather than spinning up an unsigned
replacement.

To install the recovery check on an already approved host, adapt the
`systemd/*.service` paths to that host's verified install location, then
load the user units and enable the timer. Do not use this example to bypass
a production security gate.

## Verified 2026-11-07

- Synthetic attestation and recovery tests: 16/16 passed.
- Live local deployment: RAG and ingester Docker health healthy; five signed
  SharePoint chunks with freshly verified signatures; Guard policy 14 and
  Gateway ready. RAG container no longer receives SharePoint client secret.
- Controlled *ingester-only stop/start* recovery: passed; trusted Graph sync
  resumed, signed-index health returned, Guard/Gateway remained ready.
- Real Microsoft Entra Alice/Bob permission matrix repeated on 2026-11-07
  **after** the recovery deployment: **10/10 live protected RAG decisions**
  (Alice 4 allow/1 deny, Bob 2 allow/3 deny). The five documents include
  direct, shared, group-derived, and inherited permissions; no employee
  passwords or bearer tokens were written to the RAG or repository.
- Controlled RAG-only Docker stop followed by the installed recovery
  controller: **passed**; existing RAG container restarted, 5/5 signed chunks
  validated, Guard and Gateway remained running; no host reboot.
- Controlled Human Validation Guard-only Docker restart: **passed**; application
  policy 14, Guard, Gateway, RAG, Redis, ingester health recovered. The 10/10
  live matrix above ran before this Guard-only restart; a full matrix after
  that restart was not part of this recorded test.
- An earlier 10-case live run encountered six transient Guard Layer 1 HTTP 503
  failures (fail closed), then four successful authorization decisions.
  Microsoft Graph also reported a transient error on a *different* legacy
  SharePoint sync service during the same window. The cause of the Guard 503
  has **not** been conclusively isolated. Guard /health alone is not a proof
  that every employee-authenticated request will succeed. Subsequent 10/10
  success is a recovery observation, not proof the intermittent dependency
  issue cannot recur.
- Additional targeted security regression tests: 43/43 passed (Guard OIDC,
  binding readiness, certification window and Gateway Guard-error semantics).
- **Not performed:** an actual Ubuntu reboot; production always-on host
  migration; live revoke/restore; independent source certification.

## Question-first protected RAG (2026-11-08)

The local human-validation console now defaults to natural questions without
requiring users to select files. A real signed-in employee is still required.
The retriever automatically chooses relevant signed SharePoint chunks based
on question terms, content/title overlap, and FTS5 relevance scoring. The
AccessProof Gateway still applies Layer 1 authorization before the model sees
retrieved chunks and Layer 2 verification before releasing an answer.

The optional advanced diagnostic file picker remains for controlled synthetic
Alice/Bob permission tests. Open-ended questions have no predetermined allow/
deny expectation. Unauthorized candidates are not disclosed in browser
citations or excerpts.

Live host: ~/Downloads/accessproof-human-validation-rag.
Local operator UI: http://127.0.0.1:28290 (one-time session required).
Protected RAG: http://127.0.0.1:28189/chat/protected (real bearer required).
Baseline remains disabled. The separate certified production and remote RAG
routes were not modified.

Launch the UI on the owner's laptop:
    bash ~/Downloads/accessproof-human-validation-rag/open-validation.sh

Tests:
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q deploy/local-human-validation-lab/tests/test_question_first_chat.py

Retrieval tests can run in the dependency-locked RAG Docker image with the
question-first index.py mounted read-only. The live deployment retains the
previous image tag accessproof-human-validation-rag:rollback-question-first-20261108.
Pre-change operator/index sources were backed up alongside the live files.

## Permission-aware signed retrieval cache and conversational answers (2026-11-08)

Lab behavior deployed; NOT a new production/cache certification.

- The RAG retrieves question-relevant signed chunks. Redis may cache only
  those candidate chunks for up to 45 seconds. The cache key includes
  tenant, source, application, question, diagnostic title, and atomic
  SharePoint index generation. Source attestation readiness is rechecked
  on every question.
- A retrieval cache HIT carries no old ALLOW decision or generated answer.
  Every candidate goes through AccessProof Gateway with the CURRENT employee
  identity. Gateway validates source signatures, Guard document/chunk ACLs
  and version, excludes denied chunks, and generates ONLY from the allowed
  remainder. Mixed permitted/restricted requests may answer successfully.
- Final buffered Guard release checks REMAIN REQUIRED because revocation
  can happen while inference runs; core code currently calls this Layer 2.
  Cache reauthorization is a separate pre-model concept and cannot replace
  the final release guard just by renaming it.
- The console now prioritizes the chatbot ANSWER; ALLOW/DENY and decision ID
  are inside an expandable security diagnostics section. For no accessible
  information, the visible answer does not reveal restricted filenames.
- Cache failure, corruption, oversized entries, stale signatures, revision
  change and all Gateway failures continue to fail CLOSED. Employee tokens
  and cached permission decisions are never stored in this Redis cache.
- Compose explicitly declares Redis candidate caching but no signed-answer
  return path. Its cache-return path is NOT independently certified and the
  lab must not claim production Protect or certification for this new route.
  Third-party/customer cache integrations need separate review.
- Previous lab image preserved under tag:
  accessproof-human-validation-rag:rollback-before-signed-cache-20261108
  and source copies have .before-signed-cache-20261108 suffix.

Tests: deploy/local-human-validation-lab/tests/test_protected_retrieval_cache.py,
tests/security/test_gateway_partial_cached_context.py, and existing Gateway
authorization/cached-version/answer-cache security tests.
