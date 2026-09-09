from __future__ import annotations

import re
from urllib.parse import urlparse

from . import Ctx, register, register_repro

MAX_SCRIPTS = 4  # hard request cap for js mining per asset
SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
SECRET_PATTERNS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\b(?:api[_-]?key|secret|token)[\"'\s:=]{1,4}([A-Za-z0-9_\-]{20,})"),
]
ROUTE_RE = re.compile(r"(/api/v\d+/[A-Za-z0-9_/\-]{3,60})")
MAX_ROUTES = 30


def _redact(match: str) -> str:
    """Store a short prefix + length, never the secret itself (H1 rule:
    don't exfiltrate; offer the full value on request during triage)."""
    return match[:8] + f"…(len={len(match)})"


def _same_origin(base_url: str, src: str) -> str | None:
    base = urlparse(base_url)
    url = urlparse(src)
    if not url.scheme and not url.netloc:
        path = src if src.startswith("/") else base.path.rsplit("/", 1)[0] + "/" + src
        return f"{base.scheme}://{base.netloc}{path}"
    if url.netloc == base.netloc and url.scheme in ("http", "https"):
        return src
    return None  # third-party script: never fetched as target traffic


@register("js_endpoints", "WSTG-INFO-01", "low")
def check_js(ctx: Ctx) -> list[dict]:
    if ctx.fetch is None:
        return []
    html = ctx.resp.text
    base = str(ctx.resp.request.url)
    routes: set[str] = set()
    bodies_scanned = 0
    for src in SCRIPT_SRC_RE.findall(html):
        url = _same_origin(base, src)
        if not url:
            continue
        if bodies_scanned >= MAX_SCRIPTS:
            break  # budget: at most 4 script fetches, ever
        try:
            r = ctx.fetch(url)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        bodies_scanned += 1
        ctx.fetched_js.append((url, r.text))   # share (url,body) with js_secret_leak
        routes.update(ROUTE_RE.findall(r.text))
    if not routes:
        return []
    return [{"check_id": "js_endpoints", "asset": base, "severity_hint": "low",
             "payload": {"routes": sorted(routes)[:MAX_ROUTES],
                         "context_only": True,
                         "note": "enumerated API surface; human review required "
                                 "before ANY active testing (v2 gate)"}}]


@register("js_secret_leak", "WSTG-INFO-01", "low")
def check_js_secrets(ctx: Ctx) -> list[dict]:
    """Shares the same fetch budget — implemented via js_endpoints' fetches:
    runs over the same ≤4 script bodies captured by a helper cache on ctx."""
    if ctx.fetch is None:
        return []
    # Scan the baseline HTML itself plus (budget-free) reuse of previously
    # fetched bodies stored by check_js via ctx.fetched_js: (url, text) pairs.
    texts: list[tuple[str, str]] = [(str(ctx.resp.request.url), ctx.resp.text)]
    texts += list(getattr(ctx, "fetched_js", []) or [])
    out = []
    seen = set()
    for src_url, t in texts:
        for pat in SECRET_PATTERNS:
            for m in pat.findall(t):
                value = m if isinstance(m, str) else m[0]
                if not value or value in seen:
                    continue
                seen.add(value)
                out.append({"check_id": "js_secret_leak",
                            "asset": src_url,   # evidence lives under THIS url
                            "severity_hint": "high",
                            "payload": {"redacted": _redact(value),
                                        "pattern": pat.pattern[:40]}})
    return out


register_repro("js_secret_leak", lambda sig: [
    f"Fetch {sig['asset']} (publicly served JavaScript, no auth required).",
    "Search the response for credential-shaped strings; the redacted match "
    "and its position are in the PoC capture. Full value withheld — available "
    "to the triager on request; recommend immediate rotation.",
])
