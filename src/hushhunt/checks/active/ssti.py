from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .. import register, register_repro

PROBES = ["{{7*7}}", "${7*7}", "#{7*7}"]   # 3 syntaxes, arithmetic only
FANOUT = 4


def _swap(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    q = {k: v for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
    q[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))


@register("ssti", "WSTG-INPV-18", "medium")
def check_ssti(ctx) -> list[dict]:
    """Arithmetic canaries only ({{7*7}}->49). Signal iff the evaluated form
    appears for the probe AND the same digits are absent in the baseline
    response — template engines that evaluate but the app never echoes the
    number produce no FP. No RCE-syntax probes ({}|system etc.) — policy.

    Covers BOTH: URL query params (GET) and JSON body params (POST under a
    probe grant, for openapi_post-sourced params)."""
    if ctx.fetch is None or not getattr(ctx, "params", None):
        return []
    out, seen = [], set()
    for url, param, orig in ctx.params[:FANOUT]:
        if (url, param) in seen:
            continue
        seen.add((url, param))
        try:
            base = ctx.fetch(_swap(url, param, orig or "hushxyz"))
            base_nodash = re.sub(r"\s", "", base.text)
        except Exception:
            continue
        if "49" in base_nodash:
            continue          # number already present: useless oracle
        for probe in PROBES:
            purl = _swap(url, param, probe)
            try:
                r = ctx.fetch(purl)
            except Exception:
                break
            r_nodash = re.sub(r"\s", "", r.text)
            if "49" in r_nodash and probe not in r.text:
                out.append({"check_id": "ssti", "asset": purl,
                            "severity_hint": "high",
                            "payload": {"param": param, "probe": probe}})
                break
        if ctx.post and getattr(ctx, "grant_id", None):
            for probe in PROBES:
                try:
                    r_post = ctx.post(url, json_body={param: probe}, grant_id=ctx.grant_id)
                    if "49" in re.sub(r"\s", "", r_post.text) and probe not in r_post.text:
                        out.append({"check_id": "ssti", "asset": url,
                                    "severity_hint": "high",
                                    "payload": {"param": param, "probe": probe, "format": "json"}})
                        break
                except Exception:
                    pass
    return out


register_repro("ssti", lambda sig: [
    f"GET {sig['asset']} — parameter {sig['payload']['param']!r} evaluates "
    "{{7*7}} to 49 (capture attached). Only arithmetic probes used; RCE "
    "syntax deliberately not attempted per scope rules.",
])
