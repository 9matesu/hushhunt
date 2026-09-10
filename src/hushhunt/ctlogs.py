from __future__ import annotations

from urllib.parse import urlparse

import httpx

from .scope import url_in_scope

CRTS_H = "https://crt.sh"


def _roots(includes: list[str]) -> set[str]:
    """Domains to query crt.sh for: apex roots derived from scope identifiers."""
    roots: set[str] = set()
    for inc in includes:
        host = inc[2:] if inc.startswith("*.") else inc.lstrip(".")
        if "." in host:
            parts = host.split(".")
            roots.add(".".join(parts[-2:]))
    return roots


def _candidates(body: list[dict]) -> set[str]:
    out: set[str] = set()
    for entry in body:
        for name in (entry.get("name_value") or "").splitlines():
            name = name.strip().lower()
            if not name or "*" in name:
                continue  # skip wildcard names: not connectable hosts
            out.add(name)
    return out


def discover(conn, cfg, program: dict, client_factory=None) -> list[str]:
    """Passive subdomain expansion via crt.sh — ZERO traffic to target infra.
    Every candidate must pass the scope matcher before being stored: a
    certificate name must never smuggle an out-of-scope host into the queue."""
    from .db import add_asset
    factory = client_factory or (lambda **kw: httpx.Client(**kw))
    # ponytail: strict 8s total timeout. crt.sh streams slowly when overloaded; skip quickly
    t_out = httpx.Timeout(8.0, connect=5.0)
    client = factory(timeout=t_out)
    includes, excludes = program["includes"], program["excludes"]
    added: list[str] = []
    for root in sorted(_roots(includes)):
        try:
            r = client.get(f"{CRTS_H}/", params={"q": f"%.{root}", "output": "json"}, timeout=t_out)
            if r.status_code != 200:
                continue  # crt.sh flakiness: one attempt, no retries (one no-retry policy)
            names = _candidates(r.json())
        except (httpx.HTTPError, ValueError):
            continue
        for name in sorted(names):
            if not url_in_scope(f"https://{name}/", includes, excludes):
                continue
            if add_asset(conn, program["id"], "DOMAIN", name, "ct_log"):
                added.append(name)
    return added
