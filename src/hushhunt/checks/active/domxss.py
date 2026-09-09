from __future__ import annotations

import re

from .. import register, register_repro

SINK_RE = re.compile(
    r"(innerHTML|outerHTML|document\.write(?:ln)?|location\.href\s*=|"
    r"location\.assign|eval)\s*[=(]", re.I)
SOURCE_RE = re.compile(
    r"(location\.hash|location\.search|location\.href|document\.referrer|"
    r"postMessage|window\.name)", re.I)
WINDOW = 240  # chars within which source->sink counts as a chain


def _chains(js: str) -> list[tuple[str, str]]:
    found = []
    sinks = [(m.start(), m.group(1)) for m in SINK_RE.finditer(js)]
    for s_start, s_name in sinks:
        w = js[max(0, s_start - WINDOW):s_start + WINDOW]
        m = SOURCE_RE.search(w)
        if m:
            found.append((m.group(1), s_name))
    return found


@register("xss_dom", "WSTG-CLNT-01", "low")
def check_dom_xss(ctx) -> list[dict]:
    """ZERO network: pure static taint over JS bodies the v1 miner already
    fetched (ctx.fetched_js = [(url, body)]). Context signal — the LLM triager
    decides if a chain is real; naive sinks like textContent never match."""
    out = []
    seen = set()
    for url, body in (getattr(ctx, "fetched_js", None) or []):
        for src, sink in _chains(body):
            key = (url, src, sink)
            if key in seen:
                continue
            seen.add(key)
            out.append({"check_id": "xss_dom", "asset": url,
                        "severity_hint": "low",
                        "payload": {"source": src, "sink": sink,
                                    "hint": "static chain — needs manual "
                                            "confirm in browser before report"}})
    return out


register_repro("xss_dom", lambda sig: [
    f"Open {sig['asset']}#<payload> in a browser; the value flows from "
    f"{sig['payload']['source']} into {sig['payload']['sink']} without encoding.",
    "Confirm execution manually; automated probing stopped at static analysis "
    "to stay noise-free.",
])
