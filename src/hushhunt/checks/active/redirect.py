from __future__ import annotations

import re

from .. import register, register_repro

MARKER = "hushhunt-canary.invalid"


@register("open_redirect_chain", "WSTG-CLNT-04", "low")
def check_open_redirect(ctx) -> list[dict]:
    """Only tests params the crawler already OBSERVED carrying URL-ish
    values (redirect=/url=/next=) — never invents parameters. One request
    per candidate with the canary domain. Chain bonus: if the app also has a
    known oauth-ish endpoint that trusts this redirect host, note it."""
    if ctx.fetch is None:
        return []
    out = []
    for url, param, orig in (getattr(ctx, "params", None) or []):
        if param not in ("url", "redirect", "redirect_uri", "next", "return"):
            continue
        if not _looks_like_url(orig):
            continue          # param must already behave like a URL param
        # swap the value in the RAW query string: keeps every other param's
        # original encoding intact (rebuilding via urlencode breaks probes)
        probe = re.sub(rf"([?&]{re.escape(param)}=)[^&]*",
                       rf"\g<1>https://{MARKER}/", url)
        try:
            r = ctx.fetch(probe)
        except Exception:
            continue
        loc = r.headers.get("location", "")
        if r.status_code in (301, 302, 303, 307, 308) and MARKER in loc:
            out.append({"check_id": "open_redirect_chain", "asset": probe,
                        "severity_hint": "low",
                        "payload": {"param": param, "location": loc[:120]}})
            break   # proven on this surface; chains need human context anyway
    return out


def _looks_like_url(v: str) -> bool:
    return bool(v) and ("://" in v or v.startswith("/") or "." in v)


register_repro("open_redirect_chain", lambda sig: [
    f"GET {sig['asset']} — the {sig['payload']['param']!r} parameter sends a "
    f"3xx Location to an arbitrary external host (see capture). Impact "
    "depends on login/oauth flows using this endpoint (triager decides).",
])
