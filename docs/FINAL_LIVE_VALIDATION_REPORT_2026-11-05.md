# AccessProof: final live validation report (Linux, 2026-11-05)

Windows is out of scope. Protect is **OFF**: Gate J is waiting for the owner's approval.
Evidence is in `docs/evidence/final-validation-2026-11-05/` unless stated otherwise.

## Deployed (production, verified independently after each deploy)

| Release | Commit | Status |
|---|---|---|
| **r38c-enforce-ea37fbb** | `ea37fbbb141785403b9e7fb3166305fa73847696` | **RUNNING.** api, worker and web are healthy; DB is at `x8c9d0e1f2a3`; restricted roles are preserved. |
| r38b-enforce-4899b09 | `4899b098374f` | Superseded. It fixed D-32, but production gates crashed because the API image lacked `apps.gateway`; r38c fixes that. |
| r38d-enforce-e30e287 | `e30e2871c46f` | **NOT DEPLOYED.** Preflight refused it (7 GB free, 8 GB needed). Regressions pass (1656/0 on both databases). |

r38 adds:
* production verification and enforcement of remote route certificates (migration `x8c9d0e1f2a3`, RLS);
* the D-32 fix: a fresh organization's first ACL sync failed;
* an import-closure test for the API image.

Every candidate passed the full suites (`regressions.txt`): SQLite and PostgreSQL 1653, 1654, 1656 and 1656 tests, 0 failures.

## Passed live against production

* **Production gates A–I PASS** on r38c (`production-gates-r38c-final.json`). Gate E includes `remote_routes_certified: 2 valid`.
* **Remote route certificate enforcement (production):**
  * Certificates signed by the pinned offline certifier key are verified on import: signature, all 14 checks, tenant, application, source and validity.
  * A signed live attestation of a changed RAG configuration **INVALIDATED** the LlamaIndex route (`CONFIGURATION_CHANGED:rag_runtime_config_sha256`), and **Gate E failed** (`production-gates-r38c-after-config-change-INVALIDATED.json`).
  * Re-certification restored PASS.
* **SharePoint source certificate:** production-enforced; expires **2026-12-04 15:38:15 UTC**.
* **Automatic renewal:**
  * The timer is installed (daily, `--days 30`, renews when 10 days or fewer remain).
  * A scheduled run produced `NOT_DUE` (`certificate-renewal-timer-runs.log`).
  * A forced failure (key unavailable) stopped at `PRECONDITION_FAILED` and the current certificate was preserved.

## Passed on the separate Linux server (staging EC2, Ubuntu 24.04, native Python, no Docker)

The setup:
* The RAG runs as systemd units and reaches the lab Gateway over TLS, through an SSH-over-SSM tunnel the owner opened.
* The CA is pinned, the hostname is verified, and requests are application-signed.
* Continuous signed-evidence subscription is on.

| Route | Result | Evidence |
|---|---|---|
| LangChain | **CERTIFIED 14/14** | `crossserver-langchain-certification.json` |
| LlamaIndex | **CERTIFIED 14/14** (also re-certified after the configuration test) | `crossserver-llamaindex-*.json` |

The 14 checks cover:
* authorized and unauthorized access;
* a live SharePoint revocation and the mid-request Layer 2 block;
* provenance and forged-content rejection, tampered and replayed requests;
* cache replay and cross-tenant isolation;
* direct-model and alternate-route bypass probes run **on the remote host**: no model credentials, internal model endpoints unreachable, public LLM egress recorded;
* Gateway and Guard outages, which fail closed;
* matching signed Gateway and Guard audits.

## Fresh-customer onboarding (synthetic pilot organization `0fb98b25-…`, production)

| Step | Result |
|---|---|
| 1 Register organization | **Done**, with email verification by the owner |
| 2 Connect SharePoint | **Done**, with admin consent by the owner. Directory and ACL sync are connected *after the D-32 fix*. |
| 3 Microsoft Entra | **Done**. The Guard pins the Entra issuer, audience, tenant and scope; Alice and Bob delegated tokens are verified. |
| 4 Install and pair Gateway + Guard | **Done**. Guard enrolled (policy installed). Gateway paired: the production claim was accepted and it heartbeats. |
| 5 Connect the customer's Linux RAG | **Done** (LangChain, continuous evidence, the pilot's own ingestion key) |
| 6 Automatic verification | **Ran**: production readiness is **14/25** |
| 7 Readiness and certification | **Partial.** The pilot route is **CERTIFIED 14/14** and the certificate was imported as **VALID**. The pilot's own SharePoint source certificate and the Gate E route challenge were not completed. |
| 8–10 Alice/Bob, revocation and restore | **PASS** (within the pilot certification) |
| 11 Continuous evidence refresh | **PASS** (pilot refresher with its own key and manifests) |
| 12 Audit and health | **PASS** (signed Gateway audit matches pilot Guard audits; health endpoints) |

## Defects found and fixed in this phase

* **D-32:** a new organization's first ACL sync never completed. With `autoflush=False`, a pending duplicate event became an IntegrityError. Fixed and deployed.
* **r38 gates crash:** the API image lacked `apps.gateway`. Fixed and deployed in r38c.
* **Re-certification after invalidation was impossible:** reverting a configuration reproduces the same fingerprint. Fixed in r38d (**not deployed**).

## Remaining blockers (exact)

1. **r38d deploy.** Production has 6.9 GB free and needs 8 GB. The classifier refused removing superseded images. The owner can run this on the production host to remove release images r20–r33 (r34+ are kept):
   ```
   for t in $(docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^accessproof/(api|worker|web-v2):r(2[0-9]|3[0-3])b?-'); do docker rmi "$t"; done; docker image prune -f
   ```
   Then deploy with `bash deploy/ec2-release/ship_via_ssm.sh e30e287 x8c9d0e1f2a3 r38e-enforce-e30e287`.
2. **Pilot organization:** the independent SharePoint source certificate and the Gate E route challenge and cutover. The certification tooling is wired to the reference organization's compose stack.
3. **Remote route attestation must run at least daily.** Without it, routes become `ATTESTATION_STALE` and Gate E fails. There is no scheduler yet; today it's run by hand (`remote_route_certification.py --attest` plus `remote_route_certificate.py attest`).
4. **Protect activation:** needs the owner's approval (Gate J).
5. **Cross-server depends on the owner-opened tunnel:** Claude may not open ingress tunnels.

## First Linux pilot readiness

The technical security is validated for a Linux pilot:
* Production gates A–I pass, with remote route enforcement live.
* LangChain and LlamaIndex are certified on a separate Linux server.
* A fresh organization onboarded through production up to a certified remote route.

Before onboarding a real customer:
* deploy r38d (blocker 1);
* complete the new organization's source certificate and Gate E challenge (blocker 2);
* schedule the daily route attestation (blocker 3).
