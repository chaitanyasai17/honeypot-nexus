"""
Honeypot Nexus - Rolling Window Store
Maintains sliding-window deques for stateful attack correlation.
"""

from collections import deque
from dataclasses import dataclass
import time
from typing import Callable, Any, Dict, List


@dataclass
class WindowRecord:
    timestamp: float
    event_type: str
    status: str
    endpoint: str
    username: str
    pw_fp: str
    http_status: int


class RollingWindowStore:
    def __init__(self, horizon_s: int = 900, max_items: int = 500):
        self.horizon_s = horizon_s
        self.max_items = max_items
        self._ip_windows: Dict[str, deque[WindowRecord]] = {}
        self._session_windows: Dict[str, deque[WindowRecord]] = {}

    def record(self, source_ip: str, session_id: str, event_type: str,
               status: str, endpoint: str, username: str, pw_fp: str, http_status: int):
        now = time.time()
        rec = WindowRecord(
            timestamp=now,
            event_type=event_type,
            status=status,
            endpoint=endpoint,
            username=username,
            pw_fp=pw_fp,
            http_status=http_status
        )

        # Store by IP
        if source_ip not in self._ip_windows:
            self._ip_windows[source_ip] = deque(maxlen=self.max_items)
        self._ip_windows[source_ip].append(rec)

        # Store by Session
        if session_id not in self._session_windows:
            self._session_windows[session_id] = deque(maxlen=self.max_items)
        self._session_windows[session_id].append(rec)

        self._prune(now)

    def _prune(self, now: float):
        # Periodically purge entries older than horizon_s
        cutoff = now - self.horizon_s
        for key in list(self._ip_windows.keys()):
            dq = self._ip_windows[key]
            while dq and dq[0].timestamp < cutoff:
                dq.popleft()
            if not dq:
                del self._ip_windows[key]

        for key in list(self._session_windows.keys()):
            dq = self._session_windows[key]
            while dq and dq[0].timestamp < cutoff:
                dq.popleft()
            if not dq:
                del self._session_windows[key]

    def count_ip(self, ip: str, predicate: Callable[[WindowRecord], bool], window_s: int) -> int:
        cutoff = time.time() - window_s
        dq = self._ip_windows.get(ip, deque())
        return sum(1 for r in dq if r.timestamp >= cutoff and predicate(r))

    def count_session(self, session_id: str, predicate: Callable[[WindowRecord], bool], window_s: int) -> int:
        cutoff = time.time() - window_s
        dq = self._session_windows.get(session_id, deque())
        return sum(1 for r in dq if r.timestamp >= cutoff and predicate(r))

    def distinct_ip_field(self, ip: str, field_name: str, predicate: Callable[[WindowRecord], bool], window_s: int) -> set:
        cutoff = time.time() - window_s
        dq = self._ip_windows.get(ip, deque())
        return {getattr(r, field_name) for r in dq if r.timestamp >= cutoff and predicate(r) and getattr(r, field_name)}


_window_store_instance = None


def get_window_store() -> RollingWindowStore:
    global _window_store_instance
    if _window_store_instance is None:
        _window_store_instance = RollingWindowStore()
    return _window_store_instance
