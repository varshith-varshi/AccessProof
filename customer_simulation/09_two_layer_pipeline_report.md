# Two-layer pipeline

Layer 1 passes only exact allowed source/resource/chunk metadata to the generator. Layer 2 consumes a one-time, identity/request/source-bound context and rechecks current policy before release. The twin asserts forbidden canaries are absent from model input and client output for denied/mixed/revoked cases. Uninstrumented routes cannot be protected automatically.
