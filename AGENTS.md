# AccessProof coding-agent entrypoint

**First read:** [docs/knowledge-graph/README.md](docs/knowledge-graph/README.md) and [docs/knowledge-graph/graph.json](docs/knowledge-graph/graph.json). They index components, source paths, data/security flows, maturity and limitations. For a visual overview use [docs/knowledge-graph/architecture.mmd](docs/knowledge-graph/architecture.mmd).

## Mandatory work protocol

1. Check `git status --short --branch` before editing. Never overwrite or delete another agent's in-progress tracked or untracked work. Work only on the user's requested scope.
2. Find relevant node(s) in `graph.json`, follow `source_paths`, read actual current code, integration contracts and tests. The graph is navigation, **not** definitive runtime truth.
3. Respect security boundaries: authorization is based on trusted Entra identities, source-bound permission revision, independently signed chunk provenance, and Guard Layer 1 + Layer 2. Unsupported paths must fail closed.
4. The separate typed **Owner Approval** form was removed (commit `4beeff5`). **Explicit authorized Enable Protection and all mandatory technical security gates remain.** `PROTECTED_MANUAL_VALIDATION_PENDING` and `PROTECTED_VERIFIED` are different backend-computed states.
5. Current marketable scope: **guided SharePoint + Entra pilot** on customer-approved, compatible private Linux Docker Compose RAG routes. No unsupported universal RAG, SaaS, Kubernetes, streaming/agent, Google Drive GA or third-party audit claims.
6. Do not expose secrets or customer documents. Never copy Microsoft employee sessions, private signing keys or AWS credentials to other hosts. Do not alter customer permissions, cloud resources, production traffic or deployment without explicit authorization.
7. The independent AWS certificate watcher is **monitoring-only**. Live laptop-independent signing/renewal and KMS production trust transition are not complete. Verify actual live status before claiming otherwise.
8. After edits, run targeted tests and `python3 scripts/validate_knowledge_graph.py` if graph-related files changed. Regenerate diagram with `--write-diagram` first if topology changed.

**Current claim reference:** [docs/CUSTOMER_CLAIMS_REGISTER_2026-11-07.md](docs/CUSTOMER_CLAIMS_REGISTER_2026-11-07.md). **Known limitations:** [docs/INDEPENDENT_CERTIFIER_AWS_ROLLOUT_2026-11-08.md](docs/INDEPENDENT_CERTIFIER_AWS_ROLLOUT_2026-11-08.md).

The nested `web-v2/AGENTS.md` contains additional Next.js-specific rules; read it before changing the frontend.
