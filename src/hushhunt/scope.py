from __future__ import annotations

from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}


def _match(pattern: str, host: str) -> bool:
    """pattern is a bare identifier: '*.x.com', '.x.com' or 'x.com'."""
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host == suffix or host.endswith("." + suffix)
    if pattern.startswith("."):
        return host == pattern[1:] or host.endswith(pattern)
    if pattern.startswith("*"):
        return _match("*." + pattern.lstrip("*."), host)
    return host == pattern


def url_in_scope(url: str, includes: list[str], excludes: list[str]) -> bool:
    """Default-deny gate. Everything the tool touches must pass this first."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return False
    if any(_match(e, host) or _match("*." + e, host) for e in excludes):
        # fail-safe: a bare excluded domain also excludes its subdomains
        return False
    return any(_match(i, host) for i in includes)
