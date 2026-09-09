from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from .db import count_requests_today, log_request
from .evidence import save_capture
from .scope import url_in_scope

BANNED_METHODS = {"post", "put", "patch", "delete", "options"}


class BudgetExceeded(Exception):
    pass


class OutOfScope(Exception):
    pass


class HardenedClient:
    """The single HTTP door for program-owned infrastructure.

    Enforces: scope (default-deny), 1 req/s per target, per-asset and daily
    program budgets, GET/HEAD only, no automatic redirect following (every hop
    is re-gated by the caller), full evidence capture of every request.
    """

    def __init__(self, conn: sqlite3.Connection, cfg, program: dict):
        self.conn = conn
        self.cfg = cfg
        self.program = program
        self._last = 0.0
        self._per_host: dict[str, int] = {}
        self._client = httpx.Client(
            timeout=cfg["limits.request_timeout_seconds"],
            headers={"User-Agent": cfg["limits.user_agent"],
                     "Accept": "*/*", "Accept-Language": "en"},
            follow_redirects=False,
            verify=True)

    def _check(self, url: str) -> None:
        includes = self.program["includes"]
        excludes = self.program["excludes"]
        if not url_in_scope(url, includes, excludes):
            raise OutOfScope(url)
        min_gap = 1.0 / max(self.cfg["limits.rate_per_second_per_target"], 1)
        wait = min_gap - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        host = httpx.URL(url).host
        if self._per_host.get(host, 0) >= self.cfg["limits.max_requests_per_asset"]:
            raise BudgetExceeded(f"per-asset cap hit for {host}")
        if count_requests_today(self.conn, self.program["id"]) >= \
                self.cfg["limits.daily_requests_per_program"]:
            raise BudgetExceeded(f"daily cap hit for {self.program['name']}")

    def get(self, url: str, headers: dict | None = None,
            evidence_tag: str = "probe") -> httpx.Response:
        self._check(url)
        self._last = time.time()
        host = httpx.URL(url).host
        t0 = time.time()
        err = None
        resp = None
        try:
            resp = self._client.get(url, headers=headers or {})
        except httpx.HTTPError as e:
            err = e
        finally:
            self._per_host[host] = self._per_host.get(host, 0) + 1
        ms = int((time.time() - t0) * 1000)
        if err is not None:
            req = httpx.Request("GET", url, headers=self._client.headers)
            ev = self._evidence_dir()
            save_capture(ev, req, None, err)
            log_request(self.conn, self.program["id"],
                        datetime.now(timezone.utc).isoformat(), url, "GET", 0, ms)
            raise err
        ev = self._evidence_dir()
        save_capture(ev, resp.request, resp, None)
        log_request(self.conn, self.program["id"],
                    datetime.now(timezone.utc).isoformat(), url, "GET",
                    resp.status_code, ms)
        return resp

    def _evidence_dir(self) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        # ':' is illegal in Windows path names (program ids look like 'h1:123')
        safe_pid = self.program["id"].replace(":", "_").replace("/", "-")
        return Path(self.cfg.root) / "var/evidence" / safe_pid / stamp

    # --- explicitly unsupported: mutating verbs never exist on this client ---
    def __getattr__(self, name):
        if name in BANNED_METHODS:
            raise AttributeError(
                f"hushhunt never sends {name.upper()} to program infrastructure")
        raise AttributeError(name)
