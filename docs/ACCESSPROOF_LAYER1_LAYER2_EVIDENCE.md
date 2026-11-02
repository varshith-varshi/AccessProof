# Layer 1 / Layer 2 evidence (2026-11-02)

**Evidence level: local only.** Every result below comes from the automated
suite on synthetic data (SQLite, in-process ASGI, loopback TCP). None came
from the customer SharePoint RAG or production. The primary acceptance test
(§6 of the mission: Alice/Bob × finance/engineering/shared through the real
protected RAG) was **NOT executed**: the tenant, the customer host and
production were unreachable.

| Property | Test evidence (local) | Result |
|---|---|---|
| Bob denied finance before LLM, handbook allowed | `test_adversarial_guard_boundaries::test_t1_*` | PASS |
| Header/body identity spoofing ignored | `…::test_t2_*` | PASS |
| Unauthorized content never sent to model (real TCP Gateway → fake model) | `test_gateway_real_tcp_path.py`, `test_gateway_source_neutral_real_guard.py` | PASS |
| Forged / altered attestation rejected before generation | `test_source_content_attestation.py`, `test_known_provenance_integrity_gap.py` | PASS |
| Incomplete generator trace blocked | `test_chunk_trace_reauthorization.py` | PASS |
| Late source requires own Layer 1 | `test_layer2_late_sources.py` | PASS |
| L1/L2 revision mismatch blocks release | `test_authorization_revision_binding.py` | PASS |
| Cross-source context binding | `test_cross_source_context_binding.py` | PASS |
| Static identity refused in production | `test_d03_*` (new) | PASS |
| Real Ollama model never sees denied docs | `test_gateway_real_local_ollama.py` | **SKIPPED** (no local Ollama) |
| Real SharePoint synthetic bytes into real model | `test_live_sharepoint_fixture_ollama.py` | **SKIPPED** (no tenant fixture) |
| Mission §6 tests 1–12 on the real RAG | none | **BLOCKED** |

Skipped and blocked rows are **not** counted as passing anywhere in this package.
