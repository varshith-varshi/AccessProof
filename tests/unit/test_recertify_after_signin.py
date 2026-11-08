from __future__ import annotations

from datetime import datetime, timedelta, timezone

from scripts.certifier import recertify_after_signin as r


def _ok(hours):
    return {'status': 'OK', 'session_expires_at': (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()}


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def test_starts_once_both_sessions_cover_run():
    polls = iter([{'alice': {'status': 'UNAVAILABLE'}, 'bob': _ok(30)}, {'alice': _ok(30), 'bob': _ok(30)}])
    started, c = [], Clock()
    out = r.wait_and_start(600, 3, poll=lambda: next(polls), start=lambda: started.append(1) or 0,
                           sleep=c.sleep, clock=c)
    assert out == 'STARTED' and started == [1]


def test_never_starts_without_signin_or_with_short_session():
    started, c = [], Clock()
    out = r.wait_and_start(120, 3, poll=lambda: {'alice': _ok(1), 'bob': _ok(30)},
                           start=lambda: started.append(1) or 0, sleep=c.sleep, clock=c)
    assert out == 'SIGNIN_NOT_COMPLETED' and started == []
