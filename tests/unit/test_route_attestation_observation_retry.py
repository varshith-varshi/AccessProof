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


def _early_setup(monkeypatch, tmp_path, *, hours_left, sessions):
    import os
    import sys
    from datetime import datetime, timedelta, timezone
    state = tmp_path / 'certs'
    state.mkdir()
    (state / 'r1.certificate.json').write_text(json.dumps({
        'expires_at': (datetime.now(timezone.utc) + timedelta(hours=hours_left)).isoformat(),
        'fingerprint': 'f', 'status': 'CERTIFIED'}))
    cfg = tmp_path / 'routes.json'
    cfg.write_text(json.dumps([{'name': 'r1', 'organization_id': 'o', 'application_id': 'a',
                                'route_url': 'u', 'rag_exec': 'x'}]))
    os.chmod(cfg, 0o600)
    calls, logged = [], []
    monkeypatch.setattr(renewal, 'STATE', state)
    monkeypatch.setattr(renewal, 'log', logged.append)
    monkeypatch.setattr(renewal, 'employee_sessions', lambda home: sessions)
    monkeypatch.setattr(sys, 'argv', ['x', '--config', str(cfg)])
    return calls, logged


def _session(hours):
    from datetime import datetime, timedelta, timezone
    return {'status': 'OK', 'session_expires_at': (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()}


def test_early_recertification_runs_when_sessions_cover_full_run(monkeypatch, tmp_path):
    calls, logged = _early_setup(monkeypatch, tmp_path, hours_left=72,
                                 sessions={'alice': _session(30), 'bob': _session(30)})

    def fake_certifier(route, *extra):
        calls.append(extra)
        out = Path(extra[extra.index('--out') + 1] + '.certificate.json')
        out.write_text(json.dumps({'status': 'CERTIFIED', 'fingerprint': 'g', 'expires_at': 'x'}))
        return result(code=0)
    monkeypatch.setattr(renewal, 'certifier', fake_certifier)
    monkeypatch.setattr(renewal, 'production', lambda action, route, doc: {'ok': action == 'import', 'event': 'e'})
    assert renewal.main() == 0
    assert calls and calls[0][0] == '--issue'
    assert logged[-1]['action'] == 'recertify+import' and logged[-1]['trigger'] == 'early'


def test_early_recertification_skipped_for_legacy_or_short_sessions(monkeypatch, tmp_path):
    """Unknown or too-short session lifetime never starts an optional run that could die midway."""
    for sessions in ({'alice': {'status': 'LIFETIME_UNKNOWN'}, 'bob': _session(30)},
                     {'alice': _session(1), 'bob': _session(30)},
                     {'alice': _session(30)}):
        sub = tmp_path / str(len(list(tmp_path.iterdir())))
        sub.mkdir()
        calls, logged = _early_setup(monkeypatch, sub, hours_left=72, sessions=sessions)
        monkeypatch.setattr(renewal, 'observe_attestation',
                            lambda route, cert: ({'matches': True, 'changed_fields': [], 'signature': 's'}, 'SIGNED'))
        monkeypatch.setattr(renewal, 'production', lambda action, route, doc: (
            (_ for _ in ()).throw(AssertionError('no import')) if action == 'import' else {'ok': True, 'status': {}}))
        monkeypatch.setattr(renewal, 'certifier', lambda *a, **k: (_ for _ in ()).throw(AssertionError('must not issue')))
        assert renewal.main() == 0
        assert [x['action'] for x in logged] == ['attest']


def test_failed_early_recertification_still_attests(monkeypatch, tmp_path):
    calls, logged = _early_setup(monkeypatch, tmp_path, hours_left=72,
                                 sessions={'alice': _session(30), 'bob': _session(30)})
    monkeypatch.setattr(renewal, 'certifier', lambda route, *extra: result(stderr='CHECK_FAILED', code=1))
    monkeypatch.setattr(renewal, 'observe_attestation',
                        lambda route, cert: ({'matches': True, 'changed_fields': [], 'signature': 's'}, 'SIGNED'))
    monkeypatch.setattr(renewal, 'production', lambda action, route, doc: {'ok': True, 'status': {}})
    assert renewal.main() == 1                      # surfaced for alerting
    assert [x['action'] for x in logged] == ['recertify', 'attest']
    assert logged[0]['trigger'] == 'early'


def test_due_recertification_unchanged_by_early_window(monkeypatch, tmp_path):
    """Inside the mandatory window a legacy (unknown-lifetime) live session still recertifies."""
    calls, logged = _early_setup(monkeypatch, tmp_path, hours_left=20,
                                 sessions={'alice': {'status': 'LIFETIME_UNKNOWN'}, 'bob': _session(30)})
    monkeypatch.setattr(renewal, 'certifier', lambda route, *extra: result(stderr='X', code=1))
    monkeypatch.setattr(renewal, 'observe_attestation',
                        lambda *a: (_ for _ in ()).throw(AssertionError('due failure must not attest instead')))
    assert renewal.main() == 1
    assert logged[0]['trigger'] == 'due'
