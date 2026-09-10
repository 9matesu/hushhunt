"""Egress proxy pool with round-robin rotation.

Distributes requests across multiple proxy nodes (e.g. AWS API Gateway,
residential nodes, VPS proxies) to evade single-IP rate limits and IP bans.
"""
from __future__ import annotations

import itertools
import threading


class ProxyPool:
    def __init__(self, proxies: list[str] | None = None):
        self._proxies = [p.strip() for p in (proxies or []) if p and p.strip()]
        self._lock = threading.Lock()
        if self._proxies:
            self._cycle = itertools.cycle(self._proxies)
        else:
            self._cycle = None

    def get_next_proxy(self) -> str | None:
        with self._lock:
            if not self._cycle:
                return None
            return next(self._cycle)

    @property
    def total(self) -> int:
        return len(self._proxies)
