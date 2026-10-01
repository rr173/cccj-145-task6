"""Background synchronisation loop.

Pulls/verifies on a fixed cadence.  It never raises out of the thread: every
failure is captured by :meth:`Relay.sync_once` and reflected in status.
"""

from __future__ import annotations

import threading


class Syncer(threading.Thread):
    def __init__(self, relay, interval_seconds: float = 2.0, *,
                 run_immediately: bool = True):
        super().__init__(name="audit-relay-syncer", daemon=True)
        self.relay = relay
        self.interval = max(0.05, float(interval_seconds))
        self._stop = threading.Event()
        self.run_immediately = run_immediately

    def stop(self, timeout: float | None = None) -> None:
        self._stop.set()
        self.join(timeout=timeout)

    def run(self) -> None:
        if self.run_immediately:
            self._safe_once()
        while not self._stop.wait(self.interval):
            self._safe_once()

    def _safe_once(self) -> None:
        try:
            self.relay.sync_once()
        except Exception:  # pragma: no cover - defensive; sync_once swallows
            pass
