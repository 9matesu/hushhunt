"""Hunter Knowledge Base (KB).

Ingests elite methodology, techniques, and writeup playbooks from renowned
researchers (Sam Curry, James Kettle, Frans Rosén, Orange Tsai) to augment the
AI planner with domain-specific exploitation sequences.
"""
from __future__ import annotations

from typing import Any

HUNTER_TECHNIQUES = [
    {
        "author": "Sam Curry",
        "name": "API Gateway 403/401 Override",
        "trigger": "status_403",
        "description": "Bypasses reverse proxy authorization rules using override headers and URL rewriting.",
        "probes": [
            {"header": "X-Original-URL", "pattern": "path"},
            {"header": "X-Rewrite-URL", "pattern": "path"},
            {"header": "X-Custom-IP-Authorization", "pattern": "127.0.0.1"},
            {"header": "X-Forwarded-For", "pattern": "127.0.0.1"},
            {"path_suffix": "/..;/"},
            {"path_suffix": "/%2e/"},
        ]
    },
    {
        "author": "James Kettle",
        "name": "Unkeyed Header Web Cache Poisoning",
        "trigger": "cache_headers",
        "description": "Exploits unkeyed headers (X-Forwarded-Host, X-Host) to poison shared CDN caches with attacker assets.",
        "probes": [
            {"header": "X-Forwarded-Host", "canary_suffix": ".canary"},
            {"header": "X-Host", "canary_suffix": ".canary"},
            {"header": "X-Forwarded-Scheme", "pattern": "http"},
        ]
    },
    {
        "author": "Frans Rosén",
        "name": "OAuth Redirect URI Bypass",
        "trigger": "oauth_flow",
        "description": "Bypasses lax redirect_uri regex validation in OAuth providers to leak authorization codes.",
        "probes": [
            {"param": "redirect_uri", "payload": "//attacker.invalid"},
            {"param": "redirect_uri", "payload": "https://***@attacker.invalid"},
            {"param": "redirect_uri", "payload": "/../attacker.invalid"},
        ]
    },
    {
        "author": "Orange Tsai",
        "name": "Reverse Proxy Normalization Desync",
        "trigger": "path_normalization",
        "description": "Exploits parser discrepancies between Nginx/Apache frontend and backend application servers.",
        "probes": [
            {"path_probe": "..;/"},
            {"path_probe": "/static..;/"},
            {"path_probe": "/%2e%2e/"},
        ]
    }
]


def list_hunter_techniques() -> list[dict[str, Any]]:
    return list(HUNTER_TECHNIQUES)


def get_techniques_for_target(target_info: dict[str, Any]) -> list[dict[str, Any]]:
    matched = []
    status = target_info.get("status", 200)
    headers = {str(k).lower(): str(v) for k, v in (target_info.get("headers") or {}).items()}
    url = str(target_info.get("url", "")).lower()

    # 403 / 401 gate
    if status in (401, 403):
        matched.extend([t for t in HUNTER_TECHNIQUES if t["trigger"] == "status_403"])

    # Cache presence
    if any(h in headers for h in ("x-cache", "cf-cache-status", "age", "x-varnish")):
        matched.extend([t for t in HUNTER_TECHNIQUES if t["trigger"] == "cache_headers"])

    # OAuth endpoints
    if any(k in url for k in ("oauth", "authorize", "callback", "sso", "login")):
        matched.extend([t for t in HUNTER_TECHNIQUES if t["trigger"] == "oauth_flow"])

    # Always test normalization desync if path has segments
    if "/" in url.replace("https://", "").replace("http://", ""):
        matched.extend([t for t in HUNTER_TECHNIQUES if t["trigger"] == "path_normalization"])

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for t in matched:
        if t["name"] not in seen:
            seen.add(t["name"])
            deduped.append(t)
    return deduped
