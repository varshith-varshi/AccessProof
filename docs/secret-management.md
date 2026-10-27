# Secret management

AccessProof never stores provider, AI-target or OIDC client credentials as plaintext database values.

## Development/local backend

`ACCESSPROOF_SECRET_BACKEND=local` uses AES-GCM authenticated encryption with `SECRET_ENCRYPTION_KEY`. Production configuration rejects the shipped development key.

## AWS KMS backend

`ACCESSPROOF_SECRET_BACKEND=aws-kms` enables envelope encryption:

1. AccessProof requests a fresh AES-256 data key from AWS KMS.
2. The secret is encrypted locally with AES-GCM using the plaintext data key.
3. Only the KMS-encrypted data key plus ciphertext/nonce/key metadata is persisted.
4. Decryption requires KMS to decrypt the data key.

Required configuration:

- `ACCESSPROOF_AWS_KMS_KEY_ID`
- `AWS_REGION` or `AWS_DEFAULT_REGION`
- ordinary AWS workload credentials/role outside the database

The code includes backend health validation and carries KMS key metadata. Local automated tests use a KMS contract double; no real AWS account/key was available here, so real-KMS validation is not claimed.
