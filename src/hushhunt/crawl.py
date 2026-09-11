from __future__ import annotations

import html
import re
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from .api_miner import probe_api_schemas
from .http import BudgetExceeded, HardenedClient, OutOfScope
from .scope import url_in_scope

LINK_RE = re.compile(r"<a[^>]+href=[\"']([^\"'#]+)[\"']", re.I)
FORM_RE = re.compile(r"<form[^>]+action=[\"']([^\"']+)[\"'][^>]*>(.*?)</form>",
                     re.I | re.S)
INPUT_RE = re.compile(r"<input[^>]+name=[\"']([^\"']+)[\"']", re.I)
PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]{0,40})=")
DISALLOW_RE = re.compile(r"^disallow:\s*(\S+)", re.I | re.M)


def _parse_robots(text: str) -> list[str]:
    return [m.group(1) for m in DISALLOW_RE.finditer(text or "")]


def rank_frontier(llm, program: dict, candidates: list[str]) -> list[str]:
    """Order crawl candidates by bounty likelihood. Fail-open: on any LLM
    error return input order (never block the crawl)."""
    if not candidates or llm is None:
        return list(candidates)
    import json as _json
    sys = ("You rank crawl targets for an authorized bug-bounty scan. "
           "Return ONLY JSON: {\"order\":[<exact subset of candidates, best first>]}. "
           "Prefer: api/admin/auth/payment/graphql/swagger paths over marketing pages.")
    try:
        reply = llm.complete_json(sys, _json.dumps({
            "program": program.get("id"), "candidates": candidates[:20]}))
        order = [c for c in (reply.get("order") or []) if c in candidates]
        order += [c for c in candidates if c not in order]
        return order
    except Exception:
        return list(candidates)


def crawl(cfg, conn, program: dict, transport=None,
          max_pages: int = 25, llm=None) -> dict:
    """Politeness-first BFS crawler producing the param surface that active
    checks are ALLOWED to probe (v2 rule: never invent a parameter or path —
    only crawl-observed ones are testable). Same-origin only, robots.txt
    Disallow respected (fetched once; v1 exposed_files evidence replay avoids
    a second robots request), path cap per program via HardenedClient
    budgets. Returns {'pages': n, 'params': m}."""
    hc = HardenedClient(conn, cfg, program, transport=transport)
    starts = []
    for row in conn.execute(
            "SELECT identifier FROM assets WHERE program_id=?", (program["id"],)):
        ident = row["identifier"]
        if ident.startswith("*."):
            continue
        starts.append(ident if "://" in ident else f"https://{ident}/")
    blocked: list[str] = []
    robots_url = (starts[0].rstrip("/") + "/robots.txt") if starts else None
    if robots_url and url_in_scope(robots_url, program["includes"],
                                   program["excludes"]):
        try:
            r = hc.get(robots_url)
            blocked = _parse_robots(r.text)
        except (OutOfScope, BudgetExceeded, httpx.HTTPError):
            blocked = []

    def allowed(url: str) -> bool:
        if not url_in_scope(url, program["includes"], program["excludes"]):
            return False
        path = urlparse(url).path
        return not any(path == b or path.startswith(b.rstrip("*"))
                       for b in blocked if b and b != "/")

    queue = [u for u in starts if allowed(u)]
    queue = rank_frontier(llm, program, queue)
    seen: set[str] = set()
    pages = params_n = 0
    while queue and pages < max_pages:
        url = queue.pop(0)
        norm = url.split("#")[0]
        if norm in seen:
            continue
        seen.add(norm)
        try:
            r = hc.get(norm)
        except (OutOfScope, BudgetExceeded, httpx.HTTPError):
            continue
        pages += 1
        ct = r.headers.get("content-type", "")
        if "html" not in ct and "text" not in ct and "xml" not in ct:
            continue
        base = urlparse(norm)
        for key, vals in parse_qs(base.query, keep_blank_values=True).items():
            conn.execute(
                "INSERT OR IGNORE INTO params_seen(program_id,url,param,source,"
                "sample_url,sample_value) VALUES(?,?,?,?,?,?)",
                (program["id"], base.path, key, "query", norm, vals[0]))
            params_n += 1
        for form in FORM_RE.finditer(r.text):
            action = urljoin(norm, form.group(1))
            for name in INPUT_RE.findall(form.group(2)):
                conn.execute(
                    "INSERT OR IGNORE INTO params_seen(program_id,url,param,"
                    "source,sample_url,sample_value) VALUES(?,?,?,?,?,?)",
                    (program["id"], urlparse(action).path, name, "form",
                     action, ""))
                params_n += 1
        for href in LINK_RE.findall(r.text):
            child = urljoin(norm, html.unescape(href))
            if urlparse(child).netloc == base.netloc and allowed(child):
                queue.append(child)
    # --- API schema discovery: unlock REST/GraphQL attack surface ---
    for base in starts:
        if not allowed(base):
            continue
        try:
            api_results = probe_api_schemas(hc, base)
        except (OutOfScope, BudgetExceeded, httpx.HTTPError):
            continue
        for route in api_results.get("openapi_routes", []):
            rpath = route.get("path", "")
            method = str(route.get("method", "GET")).lower()
            full_url = urljoin(base, rpath.lstrip("/")) if rpath.startswith("/") else base.rstrip("/") + "/" + rpath
            if not allowed(full_url):
                continue
            for param in route.get("params", []):
                conn.execute(
                    "INSERT OR IGNORE INTO params_seen(program_id,url,param,source,"
                    "sample_url,sample_value) VALUES(?,?,?,?,?,?)",
                    (program["id"], urlparse(full_url).path, param, f"openapi_{method}",
                     full_url, "test"))
                params_n += 1
    conn.commit()
    return {"pages": pages, "params": params_n}
