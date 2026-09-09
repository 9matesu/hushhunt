from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from . import register

API = "https://api.hackerone.com/v4"
PROBEABLE_ASSET_TYPES = {"DOMAIN", "WILDCARD", "URL"}
_DOMAIN_RE = re.compile(r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")


def _host_from_identifier(asset_type: str, identifier: str) -> str | None:
    identifier = identifier.strip()
    if asset_type == "URL":
        host = urlparse(identifier if "://" in identifier else "https://" + identifier).hostname
        return host.lower() if host else None
    if _DOMAIN_RE.match(identifier.lower()):
        return identifier.lower()
    return None  # IPv4/CIDR/mobile/unknown -> never probed in v1


def parse_policy_excludes(policy_text: str) -> list[str]:
    """Bare domains listed under an 'out of scope' heading (best-effort;
    operators must still read each program policy manually before enabling it)."""
    out: list[str] = []
    in_oos = False
    for line in (policy_text or "").splitlines():
        stripped = line.strip().strip("#*-> ").lower().rstrip(":")
        if not stripped:
            continue
        if re.match(r"^out[- ]of[- ]scope", stripped):
            in_oos = True
            continue
        if in_oos and re.match(r"^(in scope|scope$|description|overview)", stripped):
            in_oos = False
            continue
        if in_oos:
            token = stripped.split()[0].rstrip(".,;")
            if _DOMAIN_RE.match(token):
                out.append(token)
    return sorted(set(out))


def parse_scope(attributes: dict) -> tuple[list[str], list[str]]:
    includes: list[str] = []
    for b in attributes.get("program_bounties", []) or []:
        atype = (b.get("asset_type") or "").upper()
        if atype not in PROBEABLE_ASSET_TYPES:
            continue
        host = _host_from_identifier(atype, b.get("identifier", ""))
        if host and host not in includes:
            includes.append(host)
    excludes = parse_policy_excludes(attributes.get("policy", ""))
    return includes, excludes


@register
class HackerOneAdapter:
    name = "hackerone"

    def __init__(self, client_factory=None):
        self._client_factory = client_factory

    def _client(self, cfg) -> httpx.Client:
        factory = self._client_factory or (lambda **kw: httpx.Client(**kw))
        user = cfg.secret("HH_H1_USER")
        token = cfg.secret("HH_H1_API_TOKEN")
        return factory(auth=(user, token), timeout=30)

    def sync_programs(self, conn, cfg) -> int:
        """Management-API traffic — see adapters/__init__ note; not target traffic."""
        from ..db import add_asset, upsert_program
        client = self._client(cfg)
        count = 0
        page = 1
        while True:
            r = client.get(f"{API}/programs",
                           params={"page[number]": page, "page[size]": 50})
            r.raise_for_status()
            body = r.json()
            items = body.get("data", [])
            if not items:
                break
            for item in items:
                attrs = item.get("attributes", {})
                includes, excludes = parse_scope(attrs)
                if not includes:
                    continue  # nothing probeable (v1 skips non-domain scope)
                max_bounty = max((b.get("max_bounty") or 0
                                  for b in attrs.get("program_bounties", []) or []
                                  if (b.get("asset_type") or "").upper() in PROBEABLE_ASSET_TYPES),
                                 default=0)
                pi = attrs.get("policy_information") or {}
                upsert_program(conn, {
                    "id": f"h1:{item['id']}", "platform": "hackerone",
                    "name": attrs.get("name", ""), "url": attrs.get("url", ""),
                    "safe_harbor": pi.get("safe_harbor", "none"),
                    "max_bounty": max_bounty,
                    "avg_resolution_h": float(attrs.get("average_bounty_resolution_time") or 0),
                    "created_at_remote": attrs.get("created_at"),
                    "policy_text": attrs.get("policy", "") or "",
                    "scope_json": __import__("json").dumps(
                        {"includes": includes, "excludes": excludes})})
                for inc in includes:
                    atype = "WILDCARD" if inc.startswith("*.") else "DOMAIN"
                    add_asset(conn, f"h1:{item['id']}", atype, inc, "program_scope")
                count += 1
            nxt = (body.get("links") or {}).get("next")
            if not nxt:
                break
            page += 1
        return count
