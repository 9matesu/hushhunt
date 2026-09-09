from __future__ import annotations

import json

import httpx

from . import register

API = "https://api.bugcrowd.com"


@register
class BugcrowdAdapter:
    name = "bugcrowd"

    def __init__(self, client_factory=None):
        self._client_factory = client_factory

    def _client(self, cfg) -> httpx.Client:
        factory = self._client_factory or (lambda **kw: httpx.Client(**kw))
        token = cfg.secret("HH_BC_TOKEN")
        return factory(headers={"Authorization": f"Token {token}",
                                "Accept": "application/json",
                                "API-Version": "2"}, timeout=30)

    @staticmethod
    def _probeable(scope: dict) -> str | None:
        stype = (scope.get("type") or "").upper()
        ident = (scope.get("identifier") or "").strip().lower()
        if not ident:
            return None
        if stype.startswith("WILDCARD"):
            return ident if ident.startswith("*.") else "*." + ident.lstrip(".*")
        if stype.startswith("DOMAIN"):
            return ident
        if stype.startswith("URL"):
            host = httpx.URL(ident if "://" in ident else "https://" + ident).host
            return str(host).lower() if host else None
        return None  # mobile app, IP, other -> never probed in v1

    def sync_programs(self, conn, cfg) -> int:
        """Management-API traffic; not target traffic (see adapters/__init__)."""
        from ..db import add_asset, upsert_program
        client = self._client(cfg)
        count = 0
        r = client.get(f"{API}/bounties", params={"size": 100})
        r.raise_for_status()
        for item in r.json().get("results", []):
            includes: list[str] = []
            for scope in item.get("scopes", []) or []:
                host = self._probeable(scope)
                if host and host not in includes:
                    includes.append(host)
            if not includes:
                continue
            upsert_program(conn, {
                "id": f"bc:{item['id']}", "platform": "bugcrowd",
                "name": item.get("name", ""), "url": item.get("url", ""),
                "safe_harbor": "all" if item.get("is_safe_harbor") else "none",
                "max_bounty": int(item.get("max_reward") or 0),
                "avg_resolution_h": 0.0,
                "created_at_remote": item.get("created_at"),
                "policy_text": item.get("description", "") or "",
                "scope_json": json.dumps({"includes": includes, "excludes": []})})
            for inc in includes:
                atype = "WILDCARD" if inc.startswith("*.") else "DOMAIN"
                add_asset(conn, f"bc:{item['id']}", atype, inc, "program_scope")
            count += 1
        return count
