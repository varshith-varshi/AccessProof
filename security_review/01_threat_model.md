# Threat model — Layer 1, Layer 2, and cross-layer bypasses

**Security goal:** An authenticated employee must not receive data beyond their actual effective source permission via a declared and instrumented AccessProof-protected RAG pathway.

**Sensitive assets:** file/chunk content, model context, cache and conversation memory, bearer/Guard credentials, tenant policy snapshots, decision-context IDs, provenance and audit records.

**Attacker positions:** employee using their own JWT; external unauthenticated user; rogue prompt/document author; user supplying retrieval metadata or forged citations; another tenant; a compromised/misconfigured RAG integration; an outage or race during policy synchronization. Customer-admin actions and live Google APIs remain outside adversarial testing in this local audit.

## Layer 1 attack tree
Spoof subject/tenant → select different app or source → swap resource/chunk IDs or mixed provenance → skip or misorder Guard hook → allow an unknown/stale grant → forbidden bytes enter model. Reusable tests must capture **model inputs**, not only HTTP response status.

## Layer 2 attack tree
Inject answer/citation/tool lineage → submit stale/replayed decision ID → update grants between check and context consumption → downgrade Protect to Shadow during generation or retry → stream unverified partial bytes → unsafe result reaches employee. The local atomic release boundary now locks policy recheck and context consumption on a bound source. This is an authorization linearization point, not proof of atomic delivery over a network.

## Combined chains
- Alice allow → revoke effective → cached answer and forged provenance → release.
- Bob spoof Alice metadata → forbidden vector document → cite authorized handbook.
- ALPHA principal → BETA source metadata → mismatched cached context → output.
- Source 403/429/500 → SDK exception handler passthrough or unsafe retry.
- Protect L1 → Shadow L2 or Shadow regeneration → leaked buffered secret.
- Legitimate authorized dialogue → later revoked principal requests copied memory. Real customer framework memory remains unverified.

**Hard limits:** Semantic leakage without trusted provenance cannot generally be recognized by searching generated natural language; a Guard installed after an untrusted embedding/reranker cannot undo prior exposure; SDK integration does not magically cover arbitrary alternative endpoints. True source revocation latency depends on Google Drive, ACL/directory sync and enforced Guard freshness policy.
