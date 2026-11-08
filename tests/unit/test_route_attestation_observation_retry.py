"""Transient route transport failures never become counterfeit evidence."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from scripts.certifier import remote_route_attestation as renewal

CERT = Path('/tmp/example-not-real-route.certificate.json')
ROUTE = {'name': 'synthetic-staging', 'route_url': 'http://127.0.0.1:9999'}


def result(*, stderr: str = '', stdout: str = '', code: int = 1):
    return subprocess.CompletedProcess(['synthetic-certifier'],code,stdout,stderr)


def test_transient_network_failure_then_fresh_signed_observation(monkeypatch):
    attempts = [
        result(stderr='ConnectionResetError: [Errno 104] Connection reset by peer'),
        result(stdout=json.dumps({'signature': 'signed-new-observation', 'matches': True}),code=0),
    ]
    seen=[];delays=[]
    def run(route,*args):
        seen.append((route,args))
        return attempts[len(seen)-1]
    monkeypatch.setattr(renewal,'certifier',run)
    monkeypatch.setattr(renewal.time,'sleep',delays.append)
    att,state = renewal.observe_attestation(ROUTE,CERT)
    assert (att['signature'],state)==('signed-new-observation','SIGNED')
    assert len(seen)==2 and seen[0][1]==('--attest',str(CERT))
    assert delays==[3]


def test_never_retry_authorization_failure(monkeypatch):
    calls=[]
    monkeypatch.setattr(renewal,'certifier',lambda *args:(calls.append(1) or result(stderr='AccessDeniedException 403')))
    monkeypatch.setattr(renewal.time,'sleep',lambda _: (_ for _ in ()).throw(AssertionError('no backoff')))
    assert renewal.observe_attestation(ROUTE,CERT)==(None,'OBSERVATION_FAILED')
    assert len(calls)==1


def test_signed_mismatch_is_returned_to_invalidate_not_retried(monkeypatch):
    calls=[]
    response=result(stdout=json.dumps({'signature':'signed-fingerprint','matches':False,'changed_fields':['route_sha256']}))
    monkeypatch.setattr(renewal,'certifier',lambda *args:(calls.append(1) or response))
    monkeypatch.setattr(renewal.time,'sleep',lambda _: (_ for _ in ()).throw(AssertionError('no retry')))
    att,state=renewal.observe_attestation(ROUTE,CERT)
    assert state=='SIGNED' and att['matches'] is False and len(calls)==1


def test_exhaustion_fails_closed_and_never_imports_old_evidence(monkeypatch):
    calls=[];delays=[]
    monkeypatch.setattr(renewal,'certifier',lambda *args:(calls.append(1) or result(stderr='urllib.error.URLError: <urlopen error [Errno 111] Connection refused>')))
    monkeypatch.setattr(renewal.time,'sleep',delays.append)
    assert renewal.observe_attestation(ROUTE,CERT)==(None,'TRANSIENT_ROUTE_UNAVAILABLE')
    assert len(calls)==3 and delays==[3,6]


def test_malformed_signature_does_not_get_imported(monkeypatch):
    response=result(stdout='{"matches":true,"signature":null}',code=0)
    monkeypatch.setattr(renewal,'certifier',lambda *args:response)
    assert renewal.observe_attestation(ROUTE,CERT)==(None,'OBSERVATION_FAILED')


def test_recertification_refused_without_live_employee_sessions(monkeypatch, tmp_path):
    """A due re-certification must not stop Gateway/Guard or revoke SharePoint
    access when the Alice/Bob sessions it needs are gone."""
    import os, sys
    from datetime import datetime, timedelta, timezone
    state = tmp_path / 'certs'; state.mkdir()
    (state / 'r1.certificate.json').write_text(json.dumps({
        'expires_at': (datetime.now(timezone.utc) + timedelta(hours=20)).isoformat(),
        'fingerprint': 'f', 'status': 'CERTIFIED'}))
    cfg = tmp_path / 'routes.json'
    cfg.write_text(json.dumps([{'name': 'r1', 'organization_id': 'o', 'application_id': 'a',
                                'route_url': 'u', 'rag_exec': 'x'}]))
    os.chmod(cfg, 0o600)
    logged = []
    monkeypatch.setattr(renewal, 'STATE', state)
    monkeypatch.setattr(renewal, 'log', logged.append)
    monkeypatch.setattr(renewal, 'employee_sessions',
                        lambda home: {'alice': {'status': 'OK'}, 'bob': {'status': 'UNAVAILABLE'}})
    monkeypatch.setattr(renewal, 'certifier', lambda *a, **k: (_ for _ in ()).throw(AssertionError('must not run')))
    monkeypatch.setattr(sys, 'argv', ['x', '--config', str(cfg)])
    assert renewal.main() == 1
    assert logged[0]['action'] == 'recertify' and logged[0]['ok'] is False
    assert logged[0]['detail'] == 'EMPLOYEE_SESSION_UNAVAILABLE:bob'


def test_sessions_ready_requires_both_employees():
    assert renewal.employee_sessions_ready({'alice': {'status': 'OK'}, 'bob': {'status': 'OK'}})[0]
    assert not renewal.employee_sessions_ready({'alice': {'status': 'OK'}})[0]
    assert renewal.employee_sessions_ready(
        {'alice': {'status': 'LIFETIME_UNKNOWN'}, 'bob': {'status': 'OK'}})[0]  # legacy but live
