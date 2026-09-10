"""Resilient HTTP session with auto-healing re-authentication.

Intercepts 401/403 responses during stateful testing, invokes a registered
login/refresh callback to obtain fresh tokens/headers, and seamlessly replays
the failed request so test sequences do not stall on expired credentials.
"""
from __future__ import annotations

from typing import Any, Callable


class ResilientSession:
    def __init__(self, client: Any, reauth_fn: Callable[[], dict[str, str]] | None = None,
                 initial_headers: dict[str, str] | None = None):
        self.client = client
        self.reauth_fn = reauth_fn
        self.headers = dict(initial_headers or {})

    def get(self, url: str, **kwargs) -> Any:
        return self._request("get", url, **kwargs)

    def post(self, url: str, **kwargs) -> Any:
        return self._request("post", url, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> Any:
        h = dict(kwargs.pop("headers", {}) or {})
        h.update(self.headers)

        req_fn = getattr(self.client, method)
        resp = req_fn(url, headers=h, **kwargs)

        # Detect auth expiry
        if resp.status_code in (401, 403) and self.reauth_fn is not None:
            new_headers = self.reauth_fn()
            if new_headers:
                self.headers.update(new_headers)
                h.update(new_headers)
                # Replay once with fresh auth
                resp = req_fn(url, headers=h, **kwargs)

        return resp
