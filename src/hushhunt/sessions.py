from __future__ import annotations

import os
import re
from pathlib import Path

import httpx
import yaml

def _csrf_re(field: str) -> re.Pattern:
    esc = re.escape(field)
    return re.compile(
        rf"<input[^>]+name=[\"']{esc}[\"'][^>]+value=[\"']([^\"']+)[\"']"
        rf"|<input[^>]+value=[\"']([^\"']+)[\"'][^>]+name=[\"']{esc}[\"']",
        re.I)


class SessionError(Exception):
    pass


def accounts_path(cfg) -> Path:
    return Path(cfg.root) / cfg.get("sessions.file", "seeds/accounts.yaml")


def load_accounts(cfg, program_id: str) -> list[dict]:
    p = accounts_path(cfg)
    if not p.exists():
        return []
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return list(data.get(program_id) or [])


class SessionBroker:
    """Owns httpx clients with their own cookie jars, logged in ONLY with
    operator-provided throwaway accounts (passwords from env). One login per
    account; no retries on failure; scope rules identical to v1."""

    def __init__(self, program: dict, accounts: list[dict], client_factory=None):
        self.program = program
        self.accounts = {a["id"]: a for a in accounts}
        self._factory = client_factory or (lambda **kw: httpx.Client(**kw))
        self._cache: dict[str, httpx.Client] = {}

    def session(self, account_id: str) -> httpx.Client:
        if account_id in self._cache:
            return self._cache[account_id]
        acct = self.accounts.get(account_id)
        if acct is None:
            raise KeyError(f"account {account_id!r} not registered for program")
        password = os.environ.get(acct["password_env"], "")
        if not password:
            raise RuntimeError(
                f"account {account_id}: set {acct['password_env']} in env")
        client = self._factory(timeout=20, follow_redirects=False)
        from .scope import url_in_scope
        for u in (acct["login_url"],):
            if not url_in_scope(u, self.program.get("includes", []),
                                self.program.get("excludes", [])):
                client.close()
                raise SessionError(
                    f"login_url {u} outside program scope — refusing to send credentials")
        csrf = ""
        try:
            page = client.get(acct["login_url"])
            if acct.get("csrf_field"):
                m = _csrf_re(acct["csrf_field"]).search(page.text)
                if m:
                    csrf = m.group(1) or m.group(2) or ""
            data = {"username": acct["user"], "password": password}
            if csrf:
                data[acct["csrf_field"]] = csrf
            r = client.post(acct["login_url"], data=data)
        except httpx.HTTPError as e:
            client.close()
            raise SessionError(f"login transport error: {e}") from e
        if r.status_code >= 400:
            client.close()
            raise SessionError(
                f"login failed for {account_id}: HTTP {r.status_code}")
        self._cache[account_id] = client
        return client

    def close(self):
        for c in self._cache.values():
            c.close()
        self._cache.clear()
