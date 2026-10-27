# AccessProof Guard

The Guard is a customer-side policy enforcement point. It keeps a durable local
policy cache and continues applying the last installed policy if the AccessProof
control plane cannot be reached.

Required runtime configuration:

```text
ACCESSPROOF_GUARD_CONTROL_PLANE_URL=https://api.example.com
ACCESSPROOF_GUARD_ID=<guard UUID>
ACCESSPROOF_GUARD_CREDENTIAL=<one-time exchanged machine credential>
ACCESSPROOF_GUARD_JWT_ISSUER=<trusted issuer>
ACCESSPROOF_GUARD_JWT_AUDIENCE=<trusted audience>
ACCESSPROOF_GUARD_JWT_VERIFICATION_KEY=<verification key>
```

The machine credential is only used for Guard-to-control-plane synchronization;
end-user identity is always derived from the verified bearer JWT presented to
the data-plane endpoints. Do not place either secret in application source or a
browser configuration file.
