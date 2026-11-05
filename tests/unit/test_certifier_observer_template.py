"""Fail-closed constraints for optional, not-yet-provisioned certifier observer host."""
from __future__ import annotations

import json
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[2] / 'deploy/certifier/always_on_observer.template.json'


def test_candidate_is_private_encrypted_and_ssm_only():
    t = json.loads(TEMPLATE.read_text())
    resources = t['Resources']
    instance = resources['ObserverInstance']['Properties']
    assert instance['NetworkInterfaces'][0]['AssociatePublicIpAddress'] is False
    assert instance['MetadataOptions']['HttpTokens'] == 'required'
    assert instance['MetadataOptions']['HttpPutResponseHopLimit'] == 1
    assert instance['BlockDeviceMappings'][0]['Ebs']['Encrypted'] is True
    assert instance['BlockDeviceMappings'][0]['Ebs']['DeleteOnTermination'] is True
    assert resources['ObserverSecurityGroup']['Properties']['SecurityGroupIngress'] == []
    assert resources['ObserverRole']['Properties']['ManagedPolicyArns'] == [
        'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore',
    ]
    assert '"AWS::IAM::Policy"' not in TEMPLATE.read_text()
    assert 'BLOCKED_UNTIL_AUTHORIZED' in TEMPLATE.read_text()


def test_candidate_has_no_credentials_signer_or_automatic_certifier_activation():
    t = TEMPLATE.read_text().lower()
    for item in ('-----begin private key-----', 'client_secret', 'aws_access_key_id',
                 'refresh_token', 'accessproof-cert-renewal.timer', 'source_certificate_import',
                 'route_certificate_import', 'accessproof-certifier-2026-11.pem'):
        assert item not in t
    assert 'do not install certifier private keys' in t
