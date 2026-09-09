from __future__ import annotations

from . import Ctx, register, register_repro

CANARY_ORIGIN = "https://hushhunt-canary.invalid"


@register("cors_misconfig", "WSTG-CONF-07", "low")
def check_cors(ctx: Ctx) -> list[dict]:
    """ONE extra GET with a canary Origin header. Signal only on an exact
    echo of the canary, or wildcard ACAO combined with credentials — the two
    combinations that are actually exploitable, not every CORS header."""
    if ctx.fetch is None:
        return []
    origin = f"{ctx.resp.request.url.scheme}://{ctx.resp.request.url.host}"
    path = ctx.resp.request.url.path or "/"
    try:
        r = ctx.fetch(origin + path, headers={"Origin": CANARY_ORIGIN})
    except Exception:
        return []
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").lower()
    hit = None
    if acao == CANARY_ORIGIN:
        hit = "reflected_arbitrary_origin"
    elif acao == "*" and acac == "true":
        hit = "wildcard_with_credentials"
    if not hit:
        return []
    return [{"check_id": "cors_misconfig", "asset": str(r.request.url),
             "severity_hint": "medium",
             "payload": {"issue": hit, "acao": acao, "acac": acac}}]


register_repro("cors_misconfig", lambda sig: [
    f"GET {sig['asset']} with header 'Origin: {CANARY_ORIGIN}'",
    "Observe the response's Access-Control-Allow-Origin echoing the arbitrary "
    "origin verbatim (see PoC capture) — any website can read responses "
    "cross-origin for logged-in victims.",
])
