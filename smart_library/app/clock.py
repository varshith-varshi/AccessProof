from __future__ import annotations

import time


class Clock:
    """Injectable clock so tests can move time forward (due dates, staleness, expiry)."""

    def __init__(self, start: float | None = None) -> None:
        self._offset = 0.0
        self._fixed = start

    def now(self) -> float:
        base = self._fixed if self._fixed is not None else time.time()
        return base + self._offset

    def advance(self, seconds: float) -> None:
        self._offset += seconds
