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
