from __future__ import annotations

import json

from .. import register, register_repro

INTROSPECTION = json.dumps({"query": "{ __schema { queryType { name } } }"})


@register("graphql_probe", "WSTG-APIT-99", "low")
def check_graphql(ctx) -> list[dict]:
    """ONE POST under a probe grant to an endpoint the CRAWLER discovered as
    GraphQL-ish (js routes matching /graphql etc. — never guessed paths).
    Introspection open + unauthenticated = information-disclosure signal
    (usually informative; the point is surfacing the attack surface for a
    human). Depth/aliasing abuse is NOT implemented: DoS territory, v2.1+."""
    if ctx.post is None or not getattr(ctx, "graphql_urls", None):
        return []
    out = []
    for url in ctx.graphql_urls[:2]:      # never more than 2 endpoints/night
        try:
            r = ctx.post(url, json_body=json.loads(INTROSPECTION),
                         grant_id=ctx.grant_id)
        except Exception:
            continue
        if r.status_code == 200 and "__schema" in r.text:
            out.append({"check_id": "graphql_probe", "asset": url,
                        "severity_hint": "low",
                        "payload": {"issue": "introspection_open"}})
    return out


register_repro("graphql_probe", lambda sig: [
    f"POST {sig['asset']} with body {INTROSPECTION} returns the full schema "
    "(capture attached) — attacker reconnaissance is free on this endpoint.",
])
