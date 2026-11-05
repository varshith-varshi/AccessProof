from __future__ import annotations

from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from packages.crypto.aws_kms_signer import KmsEd25519Signer, KmsSignerError
from packages.crypto.remote_route_certificate import issue_attestation, verify_signed

ARN = 'arn:aws:kms:eu-north-1:111122223333:key/12345678-abcd-1234-abcd-1234567890ab'


class FakeKms:
    def __init__(self, private=None):
        self.key = private or Ed25519PrivateKey.generate()
        self.last_sign = None
        self.algo = 'ED25519_SHA_512'

    def get_public_key(self, *, KeyId):
        return {'KeyId': KeyId, 'KeySpec': 'ECC_NIST_EDWARDS25519',
                'KeyUsage': 'SIGN_VERIFY', 'SigningAlgorithms': ['ED25519_SHA_512'],
                'PublicKey': self.key.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)}

    def sign(self, **kwargs):
        self.last_sign = kwargs
        return {'KeyId': kwargs['KeyId'], 'SigningAlgorithm': self.algo,
                'Signature': self.key.sign(kwargs['Message'])}


@pytest.fixture(autouse=True)
def profile(monkeypatch):
    monkeypatch.setenv('AWS_PROFILE', 'accessproof-certifier')
    for name in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                 'AWS_SECURITY_TOKEN', 'AWS_WEB_IDENTITY_TOKEN_FILE'):
        monkeypatch.delenv(name, raising=False)


def test_kms_signature_is_standard_ed25519_and_route_attestation_verifies():
    kms = FakeKms()
    signer = KmsEd25519Signer(ARN, client=kms)
    data = b'canonical AccessProof evidence bytes'
    signature = signer.sign(data)
    signer.public_key().verify(signature, data)
    assert kms.last_sign == {'KeyId': ARN, 'Message': data, 'MessageType': 'RAW',
                             'SigningAlgorithm': 'ED25519_SHA_512'}
    cert = {'fingerprint': 'abc', 'binding': {'tenant_id': 'test', 'application_id': 'test'}}
    att = issue_attestation(cert, {}, signer, key_id='kms-certifier-2026-11',
                            now=datetime(2026, 11, 5, tzinfo=timezone.utc))
    assert verify_signed(att, {'kms-certifier-2026-11': signer.public_key()})
    assert not verify_signed(att, {'different': signer.public_key()})


def test_invalid_profiles_and_non_pinned_key_rejected(monkeypatch):
    with pytest.raises(KmsSignerError, match='PINNED'):
        KmsEd25519Signer('alias/my-certifier', client=FakeKms())
    monkeypatch.delenv('AWS_PROFILE')
    with pytest.raises(KmsSignerError, match='INDEPENDENT_CERTIFIER_PROFILE'):
        KmsEd25519Signer(ARN, client=FakeKms())
    monkeypatch.setenv('AWS_PROFILE', 'accessproof-certifier')
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'fake-value')
    with pytest.raises(KmsSignerError, match='INDEPENDENT_CERTIFIER_PROFILE'):
        KmsEd25519Signer(ARN, client=FakeKms())


def test_wrong_public_key_type_fail_closed():
    class Other(FakeKms):
        def get_public_key(self, **kwargs):
            result = super().get_public_key(**kwargs)
            result['KeySpec'] = 'ECC_NIST_P256'
            return result
    with pytest.raises(KmsSignerError, match='TYPE_OR_USAGE'):
        KmsEd25519Signer(ARN, client=Other())


def test_mismatched_signing_algorithm_and_invalid_signature_rejected():
    fake = FakeKms()
    signer = KmsEd25519Signer(ARN, client=fake)
    fake.algo = 'ED25519_PH_SHA_512'
    with pytest.raises(KmsSignerError, match='RESPONSE_INVALID'):
        signer.sign(b'test')
    other = FakeKms()
    signer = KmsEd25519Signer(ARN, client=other)
    other.key = Ed25519PrivateKey.generate()
    with pytest.raises(KmsSignerError, match='SIGNATURE_INVALID'):
        signer.sign(b'test')


def test_over_4k_never_silently_uses_prehash_variant():
    signer = KmsEd25519Signer(ARN, client=FakeKms())
    with pytest.raises(KmsSignerError, match='TOO_LARGE'):
        signer.sign(b'X' * 4097)


def test_kms_key_can_issue_existing_route_certificate_format():
    from packages.crypto.remote_route_certificate import (
        REQUIRED_CHECKS, BINDING_FIELDS, issue, verify_certificate,
    )
    kms = FakeKms()
    signer = KmsEd25519Signer(ARN, client=kms)
    binding = {name: f'synthetic-{name}' for name in BINDING_FIELDS}
    checks = [
        {'code': code, 'status': 'PASS', 'evidence': {kind: 'synthetic' for kind in kinds}}
        for code, kinds in REQUIRED_CHECKS.items()
    ]
    cert = issue(binding, checks, signer, key_id='kms-certifier-2026-11',
                 now=datetime(2026, 11, 5, tzinfo=timezone.utc), evidence_sha256='a' * 64)
    assert cert['status'] == 'CERTIFIED'
    valid, state, changed = verify_certificate(
        cert, signer.public_key(), binding, now=datetime(2026, 11, 6, tzinfo=timezone.utc),
    )
    assert (valid, state, changed) == (True, 'VALID', [])
    assert 'signature' in cert


def test_kms_signer_preserves_existing_source_certificate_wire_format(monkeypatch, capsys, tmp_path):
    import argparse
    import json
    from datetime import timedelta
    from packages.crypto import source_certificate as source
    from packages.crypto import aws_kms_signer
    from scripts import issue_source_certificate as cli
    key = Ed25519PrivateKey.generate()
    evidence = {
        'schema': source.EVIDENCE_SCHEMA,
        'organization_id': 'fixture-organization',
        'source_id': 'fixture-source',
        'profile': 'sharepoint',
        'scope_digest': 'b' * 64,
        'checks': [
            {'code': check, 'status': 'PASS', 'artifact_sha256': 'a' * 64,
             'observed_at': datetime.now(timezone.utc).isoformat()}
            for check in source.REQUIRED_CHECKS
        ],
    }
    evidence_path = tmp_path / 'synthetic-evidence.json'
    evidence_path.write_text(json.dumps(evidence))
    monkeypatch.setattr(aws_kms_signer, 'KmsEd25519Signer',
                        lambda _: KmsEd25519Signer(ARN, client=FakeKms(key)))
    args = argparse.Namespace(private_key=None, kms_key_arn=ARN,
                              key_id='kms-certifier-2026-11', evidence=evidence_path,
                              organization_id=evidence['organization_id'], source_id=evidence['source_id'],
                              profile='sharepoint', scope_digest='b'*64, days=7)
    assert cli.cmd_issue(args) == 0
    record = json.loads(capsys.readouterr().out)
    fields = source.CertificateFields(
        organization_id=record['organization_id'], source_id=record['source_id'],
        profile=record['provider_profile'], scope_digest=record['scope_digest'],
        evidence_digest=record['evidence_digest'], verifier_version=record['verifier_version'],
        certified_at=datetime.fromisoformat(record['certified_at']),
        expires_at=datetime.fromisoformat(record['expires_at']),
    )
    assert source.verify_certificate_signature(fields, record['signature'],
        {'kms-certifier-2026-11': key.public_key()})
    assert datetime.fromisoformat(record['expires_at']) - datetime.fromisoformat(record['certified_at']) == timedelta(days=7)


def test_kms_issuance_needs_distinct_registered_key_id(capsys, tmp_path):
    import argparse
    import json
    from scripts import issue_source_certificate as cli
    evidence_path = tmp_path / 'synthetic.json'
    evidence_path.write_text(json.dumps({'schema': 'synthetic'}))
    args = argparse.Namespace(private_key=None, kms_key_arn=ARN,
                              key_id='certifier-1', evidence=evidence_path,
                              organization_id='fixture', source_id='fixture',
                              profile='sharepoint', scope_digest='c'*64, days=30)
    assert cli.cmd_issue(args) == 2
    assert 'KMS_DISTINCT_PINNED_KEY_ID_REQUIRED' in capsys.readouterr().err


def test_kms_iam_policy_is_only_pinned_sign_and_get_public_key():
    import json
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] / 'deploy/certifier/iam-policy-kms-signer.template.json'
    policy = json.loads(path.read_text())
    assert [s['Action'] for s in policy['Statement']] == ['kms:GetPublicKey', 'kms:Sign']
    assert all(s['Resource'] == '__REPLACE_WITH_APPROVED_EU_NORTH_1_KMS_ED25519_KEY_ARN__'
               for s in policy['Statement'])
    assert policy['Statement'][1]['Condition']['StringEquals']['kms:SigningAlgorithm'] == 'ED25519_SHA_512'
