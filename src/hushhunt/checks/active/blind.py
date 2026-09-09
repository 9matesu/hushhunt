from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .. import register, register_repro


@register("blind_oast", "WSTG-INPV-19", "high")
def check_blind_oast(ctx) -> list[dict]:
    """SSRF/blind-injection family, PROVEN OUT-OF-BAND. Grant 'deep' + OAST
    enabled required. One HTTP canary URL per candidate param (≤3 params,
    ≤1 probe each). The tool NEVER receives a callback from the target —
    the target's own egress hits the OAST server and we poll it. Zero
    in-band exploitation, zero data movement."""
    oast = getattr(ctx, "oast", None)
    if oast is None or ctx.fetch is None or not getattr(ctx, "params", None):
        return []
    hits = []
    for url, param, _orig in ctx.params[:3]:
        token = oast.new_token(url)
        canary = oast.http_canary(token)
        parsed = urlparse(url)
        q = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}
        q[param] = canary
        probe = urlunparse(parsed._replace(query=urlencode(q)))
        try:
            ctx.fetch(probe)
        except Exception:
            continue
        for cb in oast.poll(token, timeout_s=10):
            hits.append({"check_id": "blind_oast", "asset": probe,
                         "severity_hint": "high",
                         "payload": {"param": param, "canary": canary,
                                     "callback": str(cb)[:200]}})
            break     # one callback proof per param: enough
    return hits


register_repro("blind_oast", lambda sig: [
    f"GET {sig['asset']} with {sig['payload']['param']!r} set to the OAST "
    "canary URL (attached). The server itself performed an outbound request "
    "to the canary (callback capture) — server-side fetch of attacker-"
    "controlled URL. No internal hosts were touched (scope rules).",
])
