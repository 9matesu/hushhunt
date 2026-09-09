from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .. import register, register_repro

# Conservative fingerprints: real engine errors, not the word "error".
DB_ERRORS = re.compile(
    r"pg_query|syntax error at or near|sqlite3?::?\s*\w*error|"
    r"you have an error in your sql syntax|unclosed quotation mark|"
    r"ora-\d{5}|microsoft ole db provider for sql server", re.I)

PROBES = ["1'", '1"']            # error-based: 2 probes, never more
TRUE_PROBE = "1' AND 1=1--"
FALSE_PROBE = "1' AND 1=2--"
FANOUT = 6


def _swap(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    q = {k: v for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
    q[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))


@register("sqli_error", "WSTG-INPV-05", "medium")
def check_sqli_error(ctx) -> list[dict]:
    """≤2 probes/param (quote, dquote); signal ONLY on engine error
    fingerprint appearing with the probe and not in the clean baseline."""
    if ctx.fetch is None or not getattr(ctx, "params", None):
        return []
    out, seen = [], set()
    for url, param, orig in ctx.params[:FANOUT]:
        if (url, param) in seen:
            continue
        seen.add((url, param))
        try:
            base = ctx.fetch(_swap(url, param, orig or "1"))
        except Exception:
            continue
        if DB_ERRORS.search(base.text):
            continue          # error even without payload => not our signal
        for probe in PROBES:
            probe_url = _swap(url, param, probe)
            try:
                r = ctx.fetch(probe_url)
            except Exception:
                break
            if DB_ERRORS.search(r.text):
                out.append({"check_id": "sqli_error", "asset": probe_url,
                            "severity_hint": "high",
                            "payload": {"param": param, "probe": probe,
                                        "fingerprint": DB_ERRORS.search(r.text)
                                        .group(0)[:60]}})
                break
    return out


@register("sqli_boolean", "WSTG-INPV-05", "high")
def check_sqli_boolean(ctx) -> list[dict]:
    """Grant 'deep' only. Differential TRUE/FALSE body length ≥30%, both 200.
    We prove the oracle — we NEVER extract data through it."""
    if ctx.fetch is None or not getattr(ctx, "params", None):
        return []
    out, seen = [], set()
    for url, param, _orig in ctx.params[:3]:        # tight surface
        if (url, param) in seen:
            continue
        seen.add((url, param))
        try:
            t = ctx.fetch(_swap(url, param, TRUE_PROBE))
            f = ctx.fetch(_swap(url, param, FALSE_PROBE))
        except Exception:
            continue
        if t.status_code != 200 or f.status_code != 200:
            continue
        lt, lf = len(t.text), max(len(f.text), 1)
        if abs(lt - lf) / max(lt, lf) >= 0.30:
            out.append({"check_id": "sqli_boolean", "asset": url,
                        "severity_hint": "high",
                        "payload": {"param": param, "delta_ratio":
                                    round(abs(lt - lf) / max(lt, lf), 2)}})
    return out


for _cid in ("sqli_error", "sqli_boolean"):
    register_repro(_cid, lambda sig, cid=_cid: [
        f"GET {sig['asset']} with {sig['payload']['param']}="
        f"{sig['payload'].get('probe', sig['payload'].get('param'))!r}-style "
        "payloads (attached captures show TRUE vs FALSE responses).",
        "Demonstrates an injection oracle; no data extracted (per scope rules).",
    ])
