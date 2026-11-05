"""Systemd certificate services must not inherit the user's AWS root/default profile."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / 'deploy' / 'certifier'


def test_certifier_services_pin_least_privilege_aws_profiles():
    expected = {
        'accessproof-route-attestation.service': 'accessproof-certifier',
        'accessproof-cert-renewal.service': 'accessproof-certifier',
        'accessproof-cert-renewal-pilot.service': 'accessproof-certifier',
        'accessproof-source-expiry-monitor.service': 'accessproof-certifier',
        'accessproof-remote-rag-tunnel.service': 'accessproof-staging-tunnel',
    }
    for file, profile in expected.items():
        text = (ROOT/file).read_text()
        assert text.count(f'Environment=AWS_PROFILE={profile}') == 1, file
        assert text.count('Environment=AWS_PROFILE=') == 1, file
        assert 'AWS_ACCESS_KEY_ID' not in text
        assert 'AWS_SECRET_ACCESS_KEY' not in text


def test_signer_services_are_separate_from_deployer_identity():
    for unit in (ROOT/'accessproof-route-attestation.service',
                 ROOT/'accessproof-cert-renewal.service',
                 ROOT/'accessproof-cert-renewal-pilot.service'):
        assert 'AWS_PROFILE=accessproof-production-deployer' not in unit.read_text()
