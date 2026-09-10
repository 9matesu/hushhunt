"""SPA & client-side API route extractor.

Parses HTML for <script src> references and JS bundles for hidden
/api/, /graphql, and query-param routes that static HTML regex misses.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_API_STR = re.compile(
    r"""["'`](/(?:api|graphql|gql|v\d|rest|trpc)[^"'`\s\\]*)["'`]"""
    r"""|["'`](https?://[^"'`\s\\]+/(?:api|graphql|gql)[^"'`\s\\]*)["'`]""",
    re.I)


def extract_script_urls(html: str, base_url: str) -> list[str]:
    out = []
    for m in _SCRIPT_SRC.finditer(html or ""):
        src = m.group(1).strip()
        if src.startswith("data:"):
            continue
        out.append(urljoin(base_url, src))
    return list(dict.fromkeys(out))


def extract_api_routes(js_text: str) -> list[str]:
    out = []
    for m in _API_STR.finditer(js_text or ""):
        route = m.group(1) or m.group(2)
        route = route.split("?")[0].rstrip("/;")
        if route and len(route) > 2:
            out.append(route)
    return list(dict.fromkeys(out))
