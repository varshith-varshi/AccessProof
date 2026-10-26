# Google Workspace + Drive V1 architecture

```mermaid
flowchart LR
  Operator[Workspace administrator] -->|server OAuth| API[AccessProof API]
  API -->|encrypted credential| Secrets[Secret backend]
  API -->|read Drive metadata & permissions| Google[Google Workspace / Drive]
  Google --> Sync[ACL synchronizer]
  Sync --> Policy[Versioned effective-access policy]
  Policy --> Guard[Customer-hosted AccessProof Guard]
  App[Customer RAG / retrieval service] -->|identity + document IDs| Guard
  Guard -->|allow / deny + audit event| App
  Guard -->|heartbeats, policy acks, audit| API
  API --> Web[web-v2 control plane]
```

The API owns operator OAuth material and encrypts it through the configured secret backend. `web-v2` only starts the OAuth redirect and never receives Google access tokens, refresh tokens, client secrets, or Guard credentials. `apps/api/accessproof_api/acl_sync.py` computes the access input; `apps/api/accessproof_api/app.py` publishes versioned policy; `apps/guard/accessproof_guard` installs it locally and makes the request-time decision.

V1 production source creation is deliberately constrained to `google-drive`. The API rejects alternate providers and browser-posted source credentials before persistence. This keeps the shipping scope aligned with the release boundary.
