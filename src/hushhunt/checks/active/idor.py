from __future__ import annotations

from .. import register, register_repro

MAX_OBJECTS = 3   # objects (ids) probed per path pattern, tiny by design


@register("idor", "WSTG-ATHZ-04", "high")
def check_idor(ctx) -> list[dict]:
    """ctx.session_a / ctx.session_b: httpx.Clients logged in with the
    OPERATOR's throwaway accounts (never enumerated users). ctx.owned_urls:
    [(url, account_a_fingerprint)] — object URLs account A legitimately
    visited in ITS OWN workflow (from the crawl of A's session). Signal iff
    B gets 200 on that exact URL with A's content fingerprint present.
    Read-only, no mutation, ids only from A's own surface."""
    sa = getattr(ctx, "session_a", None)
    sb = getattr(ctx, "session_b", None)
    if sa is None or sb is None:
        return []   # sessions come from the operator's grant flow; silently
                    # skipping is correct here (pipeline logs the reason)
    out = []
    for url, fingerprint in (getattr(ctx, "owned_urls", None) or [])[:MAX_OBJECTS]:
        try:
            ra = sa.get(url)                       # confirm A sees its object
            rb = sb.get(url)                       # the cross-tenant attempt
        except Exception:
            continue
        if ra.status_code != 200 or rb.status_code != 200:
            continue
        if fingerprint and fingerprint in rb.text:
            out.append({"check_id": "idor", "asset": url,
                        "severity_hint": "high",
                        "payload": {"victim": "acct_a", "attacker": "acct_b",
                                    "status": rb.status_code}})
    return out


register_repro("idor", lambda sig: [
    "As account A, note an object URL from your own legitimate workflow "
    "(e.g. an order/detail page you created).",
    f"As account B, request the SAME URL: {sig['asset']} — the server returns "
    "A's object data with B's session (captures attached). Object ids taken "
    "only from A's own surface; no enumeration performed.",
])
