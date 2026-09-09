from __future__ import annotations

import secrets
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .. import Ctx, register, register_repro

MAX_PROBES_PER_PARAM = 4
PARAM_FANOUT_CAP = 8


def _probes(token: str) -> list[str]:
    """Marker-only payloads — escalating contexts. NEVER alert()/stealer:
    the raw reflection of the marker itself is the evidence."""
    return [
        token,                      # plain echo test
        f'">{token}"<',             # attribute-break context
        f"<x>{token}</x>",          # tag-injection context
        f"'-\"-{token}-\"",         # JS-string context
    ]


@register("xss_reflected", "WSTG-INPV-01", "medium")
def check_xss_reflected(ctx: Ctx) -> list[dict]:
    """ctx.params: list[(url, param, original_value)] from the crawler.
    ctx.fetch: budgeted GET (passive cap applies). ONE signal per (url,param).
    Baseline probe (plain token) only proves reflection; a finding requires a
    probe containing HTML-special chars to appear RAW — an escaping app turns
    '<' into '&lt;' so such a probe can never appear verbatim (no FP)."""
    if ctx.fetch is None or not getattr(ctx, "params", None):
        return []
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for url, param, _orig in ctx.params[:PARAM_FANOUT_CAP]:
        if (url, param) in seen:
            continue
        seen.add((url, param))
        parsed = urlparse(url)
        token = "hush" + secrets.token_hex(4)
        vulnerable = None
        for probe in _probes(token)[:MAX_PROBES_PER_PARAM]:
            q = {k: v for k, v in parse_qs(parsed.query,
                                           keep_blank_values=True).items()}
            q[param] = [probe]
            new_url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
            try:
                r = ctx.fetch(new_url)
            except Exception:
                break
            if any(c in probe for c in "<>\"'") and probe in r.text:
                vulnerable = (new_url, probe)
                break               # proven: stop wasting probes
        if vulnerable:
            out.append({"check_id": "xss_reflected", "asset": vulnerable[0],
                        "severity_hint": "medium",
                        "payload": {"param": param, "marker": vulnerable[1]}})
    return out


register_repro("xss_reflected", lambda sig: [
    f"Open {sig['asset']} — parameter {sig['payload']['param']!r} echoes the "
    "marker without HTML encoding (capture attached).",
    "Same context executes script for a victim session; demonstrated with "
    "inert markers only per scope rules.",
])
