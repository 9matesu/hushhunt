"""bbscope sync — fallback/primary program ingestion with NO platform token.

The official HackerOne API needs a working personal token (and our account's
token kept 401-ing); bbscope.com is an hourly-refreshed public mirror of
program scopes across platforms (AGPL-licensed project, open data:
https://github.com/sw33tLie/bbscope). We poll its REST API instead:

  GET https://bbscope.com/api/v1/programs?platform=h1
  -> [{platform, handle, url, in_scope_count, out_of_scope_count, is_bbp,
       targets:[...]}]

Limitations vs the official API (documented, not hidden):
- no safe_harbor/creation-date/policy text per program => we are CONSERVATIVE:
  programs default to risk_cap='passive' and no active module ever runs
  against them until the operator adds a manual grant after reading the
  policy on the program page. (Active testing requires human input anyway.)
- targets are flattened strings (domains/wildcards/urls/ips) => classified
  by shape; only domain-ish entries become probeable assets.
"""
from __future__ import annotations

import json
import re

import httpx

from . import register

BBSCOPE = "https://bbscope.com/api/v1/programs"
_DOMAIN = re.compile(r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")
# common TLD set (heuristic): used to reject reverse-DNS mobile package names
# like "com.smallco.iosapp" whose LAST label is not a real TLD.
_TLDS = set("""com org net edu gov mil io ai co us uk de fr jp cn ru br in au ca
nl it es se no fi dk pl tr kr mx za nz pt hk sg tw id my vn me app dev cloud
tech xyz online site live shop business info biz name museum travel int eu asia""".split())


def classify_target(t: str) -> str | None:
    """Return a bare identifier (domain/wildcard/host-from-url) or None for
    non-probeable types (IP/CIDR/mobile package/other)."""
    t = (t or "").strip().lower()
    if not t or t.startswith(("ftp://", "file:")):
        return None
    if "://" in t:
        host = str(httpx.URL(t).host or "")
        t = host
    else:
        t = t.split("/", 1)[0]            # bare host/path form
    t = t.strip(".")
    if not t or not _DOMAIN.match(t):
        return None
    labels = t.lstrip("*.").split(".")
    first = labels[0]
    if first in {"com", "org", "net", "io", "app", "ai", "co"} and \
            len(labels) >= 2 and labels[-1] not in _TLDS:
        return None                        # reverse-DNS package name, not a domain
    return t


def program_includes(target_list: list[str]) -> tuple[list[str], list[str]]:
    return classify_targets(target_list)


def classify_targets(target_list: list[str]) -> tuple[list[str], list[str]]:
    """bbscope gives ONE flat list per program; out-of-scope terms are not
    separately available in the programs endpoint -> everything is includes.
    (The targets endpoints expose scope=in/out separately if ever needed.)"""
    out: list[str] = []
    for t in target_list or []:
        c = classify_target(t)
        if c and c not in out:
            out.append(c)
    return out, []


@register
class BBScopeAdapter:
    name = "bbscope"

    def __init__(self, client_factory=None, platform: str = "h1",
                 max_programs: int = 500):
        self._factory = client_factory or (lambda **kw: httpx.Client(**kw))
        self.platform = platform
        self.max_programs = max_programs

    def sync_programs(self, conn, cfg) -> int:
        client = self._factory(timeout=60)
        r = client.get(BBSCOPE, params={"platform": self.platform})
        r.raise_for_status()
        data = r.json()
        programs = data if isinstance(data, list) else data.get("programs", [])
        from ..db import add_asset, upsert_program
        count = 0
        prefix = {"h1": "h1", "bc": "bc", "it": "it", "ywh": "ywh",
                  "immunefi": "imn"}.get(self.platform, self.platform)
        for p in programs[: self.max_programs]:
            handle = str(p.get("handle", "")).strip("/")
            if not handle:
                continue
            includes, _excl = classify_targets(p.get("targets", []) or [])
            if not includes:
                continue
            pid = f"{prefix}:{handle}"
            upsert_program(conn, {
                "id": pid, "platform": f"bbscope-{self.platform}",
                "name": handle.replace("-", " ").title(),
                "url": p.get("url") or f"https://hackerone.com/{handle}",
                "safe_harbor": "unknown",     # NOT synced => honest unknown;
                # select.py treats !='none' mildly favorable; active modules
                # are blocked by risk_cap='passive' (the default) until the
                # operator READS the policy and raises the cap + grants.
                "max_bounty": 0,            # unknown => scores as non-bounty VDP
                "avg_resolution_h": 0.0, "created_at_remote": None,
                "policy_text": "(policy not synced via bbscope; READ IT ON "
                               "THE PROGRAM PAGE before any active testing)",
                "scope_json": json.dumps({"includes": includes,
                                          "excludes": []})})
            for inc in includes[:40]:
                atype = "WILDCARD" if inc.startswith("*.") else "DOMAIN"
                add_asset(conn, pid, atype, inc, "program_scope")
            count += 1
        return count
