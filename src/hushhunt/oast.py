from __future__ import annotations

import hashlib
import secrets
import time

import httpx


class OastClient:
    """Out-of-band canaries (interactsh-style) for BLIND findings: the tool
    never receives a callback payload itself — the target's own egress does.
    Zero traffic anywhere when disabled (default). Canary tokens hash the
    asset, never name it: the OAST server must not learn which program we're
    testing (data-sharing concern; see docs/SAFETY.md v2 section)."""

    def __init__(self, cfg, client_factory=None):
        self.cfg = cfg
        self.enabled = bool(cfg.get("oast.enabled", False))
        self.server = str(cfg.get("oast.server", "")).rstrip("/")
        self._factory = client_factory or (lambda **kw: httpx.Client(**kw))

    def new_token(self, asset: str, nonce: str | None = None) -> str:
        nonce = nonce or secrets.token_hex(4)
        digest = hashlib.sha1(asset.encode()).hexdigest()[:16]
        return f"hush-{digest}-{nonce}"

    def dns_canary(self, token: str) -> str:
        return f"{token.replace('hush-', 'h.')}.oast.local"

    def http_canary(self, token: str) -> str:
        # the URL we inject as a probe payload (points at the OAST server)
        return self.server + f"/hit/{token}"

    def poll(self, token: str, tag: str | None = None,
             timeout_s: float | None = None) -> list[dict]:
        if not self.enabled:
            return []
        timeout_s = timeout_s or self.cfg.get("oast.poll_timeout_seconds", 5)
        try:
            client = self._factory(timeout=timeout_s)
            r = client.get(f"{self.server}/api/requests", params={"match": token})
            if r.status_code != 200:
                return []
            reqs = r.json().get("requests", []) or []
        except (httpx.HTTPError, ValueError):
            return []
        if tag:
            reqs = [q for q in reqs if tag in str(q)]
        return reqs


class FakeOast(OastClient):
    """Offline twin: fire() injects a callback, poll() returns it. Tests for
    blind checks use this — no interactsh dependency in CI."""

    def __init__(self, cfg=None):
        super().__init__(cfg or {"oast": {}}, client_factory=None)
        self.enabled = True
        self.server = "http://fake.oast"
        self._hits: dict[str, list[dict]] = {}

    def fire(self, token: str, interaction: dict) -> None:
        self._hits.setdefault(token, []).append(interaction)

    def poll(self, token: str, tag: str | None = None,
             timeout_s: float | None = None) -> list[dict]:
        out = list(self._hits.get(token, []))
        self._hits[token] = []          # consume: each callback matches once
        if tag:
            out = [q for q in out if tag in str(q)]
        return out
