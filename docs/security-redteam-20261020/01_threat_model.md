# Threat model — two-layer authorization

## Assets
Protected customer documents and synthetic canaries; stable employee identity; document source IDs; policy decisions; machine enrollment secrets; audit metadata and tenant-scoped reports.

## Attacker capabilities in executed tests
- Bob has a valid low-privilege synthetic JWT and can send arbitrary headers, API bodies and retrieval/source IDs.
- Model/retrieval data can contain forbidden synthetic canaries, wrong source references, untrusted provenance and late tool sources.
- An operator may change an application source binding while a request is in flight, including a colliding resource ID.
- Simulated outages, invalid Guard HTTP responses and status/model-stream errors occur.
- No external targets, real document content or tokens were used.

## Attack trees
**Layer 1:** spoof principal -> forge file/source metadata -> mix allowed/denied documents -> exploit stale or missing policy -> reach model before authorization.
**Layer 2:** forge citation/lineage -> use decision after revocation/source rebinding -> downgrade Protect to Shadow -> stream bytes before decision -> exfiltrate output.
**Combined:** obtain stale Layer 1 allow -> swap source under same resource ID -> attach apparently valid provenance -> release forbidden content.

## Defenses verified locally
JWT issuer/audience and tenant tests; exact bound application/source; deny by default; reauthorization at Layer 2; buffered output; one-time contexts; fail-closed SDK errors; new source-ID binding for saved contexts.

## Limitations
Provenance is only as trustworthy as the customer adapter's actual trace. Arbitrary semantic leaks cannot be ruled out by reference/citation checking. A RAG path which skips the SDK remains outside AccessProof protection. Real provider propagation and 24/7 SLAs were not measured.