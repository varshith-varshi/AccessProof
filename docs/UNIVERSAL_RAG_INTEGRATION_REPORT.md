# Universal RAG Integration: validation report (2026-11-04)

Branch `claude/universal-rag` is based on the realtime line (D-31 included). Nothing was deployed to
production. Protect was not activated, no Microsoft permissions were added, and production firewall
rules were not changed. All data is synthetic (lab SharePoint fixtures, Alice and Bob test identities).

**Status legend:**
* **TESTED**: executed for real and passed, with evidence in `docs/evidence/universal-rag-2026-11-04/`.
* **PARTIAL**: executed, but not in the full target topology.
* **BLOCKED**: needs an approval or infrastructure that was not available.
* **NOT TESTED**: not executed.
* **UNSUPPORTED**: not implemented.

## Summary

| # | Requirement | Status | One-line reason |
|---|---|---|---|
| 1 | Remote RAG applications on other machines | **PARTIAL** | Certified end to end from an isolated network namespace on the lab host. The real separate Ubuntu server is reachable, but the tunnel to it is **BLOCKED** pending approval. |
| 2 | Windows RAG with a Linux Gateway/Guard | **NOT TESTED** | No Windows host is available. A portable suite and a manual Windows CI workflow are ready, but have not been run. |
| 3 | Secure cross-host Gateway | **TESTED** | TLS, workload HMAC auth, integrity, replay, rate limit, tenant isolation, network restriction and signed audit. mTLS is implemented but not exercised live. |
| 4 | LangChain plug-and-play | **TESTED** | Package, docs, unit tests, and a live remote route **CERTIFIED 14/14**. |
| 5 | LlamaIndex plug-and-play | **TESTED** | Package, docs, unit tests, and a live remote route **CERTIFIED 14/14**. |
| 6 | Automated remote route certification | **TESTED** | 14 evidence-backed checks, a signed result, binding invalidation, and an unsafe route rejected. |

## What was built (commits on `claude/universal-rag`)

| Commit | Content |
|---|---|
| b60f88d | Remote Gateway exposure: `ACCESSPROOF_GATEWAY_EXPOSURE=remote` fails at startup without TLS and ≥32-byte client keys. ap-req-v1 HMAC signs the method, path, timestamp, nonce, body hash and employee-token hash. Adds a single-use nonce cache that fails closed when full, a per-client rate limit, and `serve.py` with its own TLS (optional mTLS). |
| e49a1c8 | `integrations/rag-clients/python`: the `accessproof-rag` client, stdlib-only and OS-independent, with LangChain and LlamaIndex adapters, typed fail-closed errors, client-side provenance enforcement and an HTTPS-only rule. |
| a7ae764 | A signed, hash-chained Gateway audit log (Ed25519 per record, sha256 chain). It stores identifiers, statuses and hashes only, and **no response is released if it cannot be audited**. Also adds the reference remote RAG server (plain, LangChain, LlamaIndex). |
| (see log) | Remote route certification: the decision logic, the binding, the signed certificate and the live runner. Also a portable Windows/macOS/Linux suite and a manual workflow. |

## Requirement 3: secure cross-host Gateway (TESTED)

* **TLS:** TLS 1.2 or later. The Gateway serves its own certificate, signed by a private CA. The client pins that CA bundle and refuses plain HTTP to any non-loopback host, and the certifier probes plain HTTP and requires it to be refused.
  * Finding: the first lab CA lacked RFC 5280 key-usage extensions, and Python 3.13+ rejects such CAs (`VERIFY_X509_STRICT`). The CA and server certificate were re-issued compliant. Customer Gateway certificates must be RFC 5280 compliant.
* **Workload authentication:** every `/v1/*` route requires a per-application HMAC signature.
  * Tested live: unsigned, wrong secret, unknown client, tampered body, swapped employee token, expired, wrong path, replayed. Each is rejected with 401 and makes **0 Guard calls and 0 model calls**.
  * Rate limiting is per client (429).
* **Employee identity:** still verified by the Guard (Entra delegated token, `oid` binding). A valid application signature with an unauthorized employee is still denied.
* **Integrity and provenance:**
  * The signature covers the exact body bytes.
  * Chunk content is verified against trusted-ingestion attestations. Altered content, and content signed by a rogue key under the trusted `kid`, are rejected with `SOURCE_CONTENT_ATTESTATION_FAILED` and 0 model calls.
* **Tenant isolation:** another tenant's application id, and another tenant's source, are both rejected with 0 model calls.
* **Network restriction:** the certifier enforces this; it doesn't assume it. See requirement 6, DIRECT_MODEL_BYPASS_ABSENT.
* **Replay protection:** nonce plus timestamp at the Gateway. Protected answers are never cached, and a repeated question is re-authorized and re-generated with a new decision id.
* **Not exercised live:** mTLS (`ACCESSPROOF_GATEWAY_TLS_CLIENT_CA_FILE`) is implemented in `serve.py` and in the client (`client_cert`/`client_key`), but has not run against a live Gateway.

## Requirements 4 and 5: LangChain and LlamaIndex (TESTED)

* **Install:** `pip install "accessproof-rag[langchain]"` or `"accessproof-rag[llamaindex]"`. See `integrations/rag-clients/python/README.md`, which has examples for plain Python, LangChain `AccessProofRAG` (a Runnable over your existing retriever), and LlamaIndex `AccessProofQueryEngine` (a CustomQueryEngine over your existing retriever).
* **Executable tests:**
  * `integrations/rag-clients/python/tests`: 10 tests against the real Gateway and Guard apps in remote mode. Covers interoperability of the signature vectors, allow and deny, wrong secret, forged chunk, unreachable Gateway, and both adapters (exactly one model call: Alice yes, Bob no).
  * `tests_portable`: 7 tests with no AccessProof server code, run on Linux. Includes a TLS mock Gateway with independent HMAC verification, and the reference RAG server run as a real subprocess for plain, LangChain 1.7.4 and LlamaIndex 0.14.25.
* **Live:** both adapters ran in the reference remote RAG and were each **CERTIFIED 14/14** (requirement 6).

## Requirement 6: automated remote route certification (TESTED)

`apps/gateway/accessproof_gateway/remote_route_certification.py` is the decision logic: 20 unit tests. `scripts/live/remote_route_certification.py` is the live runner.

* **Evidence, not HTTP:** each check declares the evidence it requires:
  * the model-context witness (which documents actually reached the model);
  * Guard audit rows by request id (Layer 1 and Layer 2);
  * the Gateway's signed audit log, with its chain verified on every read;
  * the provider change record;
  * active probes on the RAG host.

  A check with any evidence missing fails. UNOBSERVABLE fails. A missing check fails. The unit test `test_http_success_without_independent_evidence_does_not_certify` covers this.
* **Binding:** the application, route method, path and URL, client id, framework and version, client package, RAG code hash, **RAG runtime configuration hash**, platform, Gateway URL, **observed Gateway TLS certificate**, exposure mode, audit public key, Gateway image, Guard image, Guard identity configuration, source id and source scope digest.
  * `--verify` recomputes the binding from the live deployment.
  * Any difference returns `INVALIDATED_CONFIGURATION_CHANGED` and names the changed fields. Certificates also expire after 7 days.
  * **Live demonstration:** VALID, then one unsafe flag added on the same code gives INVALIDATED (`rag_runtime_config_sha256`), then the original configuration restored gives VALID again.

### Live results (real SharePoint, real Entra tokens, real Guard r35 image, remote-mode TLS Gateway)

| Check | LangChain | LlamaIndex | Unsafe variant* |
|---|---|---|---|
| AUTHORIZED_ACCESS_RELEASED | PASS | PASS | PASS |
| UNAUTHORIZED_ACCESS_DENIED (Bob→finance, Alice→engineering) | PASS | PASS | PASS |
| REVOKED_DOCUMENT_DENIED (live SharePoint revoke, then restore) | PASS | PASS | not run |
| MIDREQUEST_LAYER2_BLOCKED | PASS | PASS | not run |
| TRUSTED_PROVENANCE_VERIFIED | PASS | PASS | PASS |
| FORGED_CONTENT_REJECTED | PASS | PASS | PASS |
| TAMPERED_OR_REPLAYED_REQUEST_REJECTED | PASS | PASS | PASS |
| CACHE_REPLAY_PREVENTED | PASS | PASS | PASS |
| CROSS_TENANT_ISOLATED | PASS | PASS | PASS |
| DIRECT_MODEL_BYPASS_ABSENT | PASS | PASS | **FAIL** (`OPENAI_API_KEY` present, synthetic value) |
| ALTERNATE_ROUTES_PROTECTED | PASS | PASS | **FAIL** (`/search`, `/chat/direct` leak chunk text) |
| FAIL_CLOSED_GATEWAY_UNAVAILABLE (network cut) | PASS | PASS | PASS |
| FAIL_CLOSED_GUARD_UNAVAILABLE (network cut) | PASS | PASS | PASS |
| GATEWAY_GUARD_AUDIT_MATCH | PASS | PASS | PASS |
| **Result** | **CERTIFIED** | **CERTIFIED** | **NOT_CERTIFIED** |

\*The unsafe variant ran without the revocation phase, to avoid an extra SharePoint change. The verdict is NOT_CERTIFIED on the two unsafe paths alone. Its protected `/chat` route passes every functional check, which shows that a working main route doesn't certify a host that exposes a bypass.

**Mid-request Layer 2 (LangChain run):**
1. The request was admitted at Layer 1 with the finance document in the model context (witness).
2. The model answer was held, and the Guard stopped allowing the document during the hold (12:52:44).
3. Layer 2 blocked the release: the Guard audit shows `layer2 block AUTHORIZATION_REVISION_CHANGED`, and the Gateway's signed audit shows a 503 for the same request id.
4. Stable denial followed. The post-revocation route answer contained no finance document, and Alice's access was restored at 12:54:05.

**Findings the certifier caught (all real):**
1. **A direct-model bypass in the first lab topology.** The RAG container could reach the host's Ollama bridge (`192.168.144.1:11436`), which needs no credentials (`remote-route-certification-dry-run-findings.json`). The certifier refused. Fix: the RAG host now sits on an internal-only network that reaches only the Gateway, with a TCP relay in front standing in for the customer's load balancer.
2. **Attestation TTL.** Trusted-ingestion attestations expire after 30 minutes. A static export stopped working at expiry, and the Gateway correctly refused it (`...-unsafe-expired-attestations.json`). **Integration gap: remote RAG hosts need a continuous attestation refresh feed from trusted ingestion.** That feed isn't built yet; in the lab the index was re-exported by hand.
3. **Secret exposure.** A client secret passed as an environment variable remains readable in `/proc/<pid>/environ` to anything running as the same user. The server now takes `--client-secret-file`.

## Required end-to-end validation

| Scenario | Status | Notes |
|---|---|---|
| Ubuntu RAG on a separate server | **BLOCKED** | The staging EC2 host (Ubuntu 24.04, no inbound rules) was reached over SSH-over-SSM using a 60-second EC2 Instance Connect key. Two steps were refused by the session's safety classifier and **were not worked around**: installing a persistent SSH key, and opening the reverse tunnel so the remote RAG could reach the lab Gateway. Exposing a lab service to a cloud host needs your approval. The same certifier runs unchanged against that host once a network path is approved (`--route-url`, `--rag-exec "ssh … python3"`). |
| Windows RAG to a Linux Gateway (actual Windows) | **NOT TESTED** | No Windows host. Linux simulation is not claimed as Windows validation. Ready to run: `integrations/rag-clients/python/ci/rag-client-portable.yml` (copy to `.github/workflows/`; this session's token cannot push workflow files; manual `workflow_dispatch`, windows/ubuntu/macos × Python 3.10/3.13). The host probe for DIRECT_MODEL_BYPASS_ABSENT reads `/proc`; on Windows it is UNOBSERVABLE, so Windows RAG hosts **cannot be certified yet** (fail closed). A Windows probe agent is **UNSUPPORTED**. |
| LangChain | **TESTED** | Live certified (isolated namespace, lab host). |
| LlamaIndex | **TESTED** | Live certified (isolated namespace, lab host). |
| Cross-host revocation and Layer 2 | **PARTIAL** | Exercised over a real network hop between separate network namespaces, through a TLS Gateway, with a live SharePoint revocation. It did not cross physical hosts (see the BLOCKED row). |
| Automated remote route certification, including unsafe route rejection | **TESTED** | See above. |

## Remaining limitations (honest list)

* **Production integration:** route certificates are signed by a lab certifier key (`~/.ap-id/route-certifier.key`). The production control plane does not yet import or enforce remote route certificates. That needs a deploy, which wasn't authorized. Protect activation still relies on the existing Gate E (reference route).
* **Gateway audit key custody:** the audit signing key lives on the Gateway host. It proves the Gateway's records weren't altered after writing, not that a compromised Gateway host told the truth. Guard audits, uploaded over the Guard's authenticated channel, are the independent cross-check, and the certifier requires them to match.
* **Cross-tenant identity:** tested by application id and foreign source. A real second Entra tenant identity wasn't available.
* **D-31 revision churn on production r35:** positive requests sometimes fail closed with `AUTHORIZATION_REVISION_CHANGED`. The runner retries these (at most 4 times, every attempt recorded). The fix is in r36b (regressions SQLite 1576/0 and PostgreSQL 1581/0), which hasn't been deployed.
* **Audit middleware buffering:** in audited mode the middleware buffers responses before release, including SSE. The answer was already fully buffered before Layer 2, so security is unchanged, but time-to-first-byte grows slightly.
* **Lab resources left running:** `ap-remote-gateway`, `ap-remote-rag-{langchain,llamaindex,unsafe}`, `ap-remote-lb-*`, and the networks `ap-remote-edge` and `ap-remote-front`. These are synthetic and local only.
