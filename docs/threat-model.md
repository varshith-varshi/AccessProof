# Threat model

| Threat | Primary mitigation |
|---|---|
| Malicious tenant attempts cross-tenant object access | Server-side membership check on every tenant resource; 404 on foreign run; tenant-isolation tests |
| Compromised runner secret | Hashed runner credential, explicit runner/project binding, revocation field, typed jobs only |
| Leaked OAuth/provider token | AES-GCM at rest, never returned by read APIs, no secret logging, dedicated test boundaries |
| SSRF via generic AI target | HTTPS-only cloud mode, DNS/IP checks, redirects disabled, private URLs require runner |
| Malicious webhook endpoint | HTTPS/SSRF validation, bounded timeout/retries; signed outbound payloads |
| Tampered report | SHA-256 report/evidence hashes; Ed25519 signing is not yet enabled in this build |
| Unauthorized provider mutation | Explicit boundary, mutation acknowledgement, adapter-owned provider IDs |
| Accidental deletion | Only tracked resources are deleted; cleanup does not use name-pattern matching |
| Poisoned AI output | Deterministic canary/resource/citation oracle; LLM is never the sole PASS/FAIL judge |
| AI returns unexpected customer data | Raw response persistence is disabled by default; reports retain derived evidence only |
| Replay of runner registration token | Registration token is one-time and expiration checked |
| Replay of webhook | Signed timestamp with bounded verification window |
| Password/database compromise | PBKDF2 password hashing; bearer/API tokens stored as hashes |
