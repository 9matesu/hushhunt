from __future__ import annotations

import re

from . import Ctx, register, register_repro

# Exact-path allowlist ONLY — no fuzzing, no enumerated wordlists.
ALLOWED_PATHS = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
                 "/.git/config", "/.env"]
_ENV_LINE = re.compile(r"(?m)^[A-Z_]{3,}=\S+")


def _origin(resp) -> str:
    req_url = resp.request.url
    return f"{req_url.scheme}://{req_url.host}"


@register("exposed_files", "WSTG-CONF-03", "passive")
def check_exposed_files(ctx: Ctx) -> list[dict]:
    """Uses ctx.fetch (HardenedClient.get) — scope + budget enforced upstream.
    Request count is provably <= len(ALLOWED_PATHS)."""
    if ctx.fetch is None:
        return []
    origin = _origin(ctx.resp)
    out: list[dict] = []
    for path in ALLOWED_PATHS:
        try:
            r = ctx.fetch(origin + path)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        body_head = r.text[:200]
        if "<html" in body_head.lower():
            continue  # soft-404 catch-all page, not a real file
        if path == "/.git/config" and not (body_head.startswith("[core]")
                                           or body_head.startswith("[remote")):
            continue
        if path == "/.env" and not _ENV_LINE.search(r.text):
            continue
        out.append({"check_id": "exposed_files", "asset": origin + path,
                    "severity_hint": "high",
                    "payload": {"path": path, "status": r.status_code,
                                "preview": r.text[:120]}})
    return out


register_repro("exposed_files", lambda sig: [
    f"Send a single GET request to {sig['asset']}",
    "Observe HTTP 200 returning the file content shown in the PoC capture.",
])
