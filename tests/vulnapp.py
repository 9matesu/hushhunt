"""A deliberately vulnerable mock SaaS for offline active-check testing.
Served via httpx.MockTransport — no sockets, deterministic, zero real risk.
DO NOT ever point this at a real program. Emulates per path:
  /search?q=          reflected XSS (raw echo, no encoding)
  /item?id=           SQL error fingerprint on quote; boolean delta 1=1 vs 1=2
  /render?tpl=        SSTI: {{7*7}} / ${7*7} -> '49'
  /login              GET csrf form; POST sets session cookie + X-JWT header
  /api/orders/<id>    IDOR: returns ANY order for any logged-in session
  /api/profile        POST mass-assignment: stores arbitrary JSON fields
  /redirect?url=      open redirect
  /graphql            introspection open; {viewer{name}} returns owner
  /static/app.js      DOM XSS (location.hash -> innerHTML); API routes
  /robots.txt         Disallow: /private/   (crawler must respect)
"""
from __future__ import annotations

import base64
import json
import re

import httpx

ORDERS = {"1": ("order-ownerA", "acct_a"), "2": ("order-ownerB", "acct_b")}
PROFILE: dict = {}
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiJhY2N0X2EifQ.i1P1Yh2Wp1uM0hS1s1N0YhQ3B1Z3l4Z0U")


def logged_in(req: httpx.Request) -> str | None:
    """Returns the account id ('acct_a'/'acct_b') behind the session cookie."""
    cookie = req.headers.get("cookie", "")
    m = re.search(r"session=ok_([ab])", cookie)
    if not m:
        return None
    return "acct_" + m.group(1)


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _jwt_parts(tok: str):
    try:
        h, p, s = tok.split(".")
        return json.loads(_b64d(h)), json.loads(_b64d(p)), s
    except Exception:
        return None


def _hmac_b64(hdr, claims, secret: str) -> str:
    import hashlib
    import hmac as _hmac
    body = (base64.urlsafe_b64encode(json.dumps(hdr, separators=(",", ":")).encode())
            .rstrip(b"=").decode() + "." +
            base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode())
            .rstrip(b"=").decode())
    return base64.urlsafe_b64encode(
        _hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()


def handler(req: httpx.Request) -> httpx.Response:
    path, params = req.url.path, req.url.params
    hdrs: list[tuple[str, str]] = [("Content-Type", "text/html")]
    if path == "/search":
        return httpx.Response(200, text=f"<h1>Search: {params.get('q', '')}</h1>",
                              headers=hdrs, request=req)
    if path == "/item":
        i = params.get("id", "")
        if ("'" in i or '"' in i) and not re.search(r"\b1\s*=\s*[12]\b", i):
            return httpx.Response(500, text="pg_query: syntax error at or near '\"'",
                                  headers=hdrs, request=req)
        if re.search(r"\b1\s*=\s*1\b", i):
            body = "ORDER " + ORDERS["1"][0] + ("pad" * 40)   # TRUE: long
            return httpx.Response(200, text=body, headers=hdrs, request=req)
        if re.search(r"\b1\s*=\s*2\b", i):
            return httpx.Response(200, text="empty", headers=hdrs, request=req)
        if "'" in i or '"' in i:
            return httpx.Response(500, text="pg_query: syntax error at or near '\"'",
                                  headers=hdrs, request=req)
        return httpx.Response(200, text="ORDER " + ORDERS.get(i, ("none", ""))[0],
                              headers=hdrs, request=req)
    if path == "/render":
        tpl = params.get("tpl", "")
        out = re.sub(r"\{\{\s*7\*7\s*\}\}", "49",
                     re.sub(r"\$\{7\*7\}", "49", tpl))
        return httpx.Response(200, text=f"Rendered: {out}", headers=hdrs, request=req)
    if path == "/login":
        if req.method == "GET":
            return httpx.Response(
                200, text='<form><input name="authenticity_token" value="tok123">'
                          '</form>', headers=hdrs, request=req)
        body = req.content or b""
        if b"password=hush" in body and b"username=acct_" in body and b"tok123" in body:
            who = "a" if b"username=acct_a" in body else "b"
            return httpx.Response(302, request=req, headers=[
                ("Location", "/"), ("Set-Cookie", f"session=ok_{who}; Path=/"),
                ("X-JWT", JWT)])
        return httpx.Response(401, text="bad", request=req)
    if path.startswith("/api/orders/"):
        who = logged_in(req)
        if not who:
            return httpx.Response(401, text="login", request=req)
        oid = path.rsplit("/", 1)[-1]
        if oid not in ORDERS:
            return httpx.Response(404, json={"error": "missing"}, request=req)
        name, owner = ORDERS[oid]
        # VULNERABLE: any session reads any order
        return httpx.Response(200, json={"order": name, "owner": owner},
                              request=req)
    if path == "/api/whoami":
        auth = req.headers.get("authorization", "")
        tok = auth.removeprefix("Bearer ").strip()
        data = _jwt_parts(tok)
        if data:
            hdr, claims, sig = data
            # VULNERABLE: accepts alg:none OR weak shared secret 'hush'
            if hdr.get("alg") == "none":
                return httpx.Response(200, json={"whoami": claims.get("sub")},
                                      request=req)
            if (hdr.get("alg") == "HS256"
                    and sig == _hmac_b64(hdr, claims, "hush")):
                return httpx.Response(200, json={"whoami": claims.get("sub")},
                                      request=req)
        return httpx.Response(401, json={"error": "bad token"}, request=req)
    if path == "/api/profile":
        who = logged_in(req)
        if not who:
            return httpx.Response(401, text="login", request=req)
        if req.method == "GET":
            return httpx.Response(200, json=PROFILE, request=req)
        try:
            body = json.loads(req.content or b"{}")
        except ValueError:
            return httpx.Response(400, json={"error": "bad json"}, request=req)
        PROFILE.update(body)
        return httpx.Response(200, json={"saved": True}, request=req)
    if path == "/api/profile-strict":
        # schema-whitelisted counterpart: unknown fields are ignored entirely
        if not logged_in(req):
            return httpx.Response(401, text="login", request=req)
        if req.method == "GET":
            return httpx.Response(200, json={"name": "acct"}, request=req)
        return httpx.Response(200, json={"saved": "name"}, request=req)
    if path == "/redirect":
        return httpx.Response(302, request=req,
                              headers=[("Location", params.get("url", "/"))])
    if path == "/graphql":
        body = (req.content or b"").decode("utf-8", errors="replace")
        if "__schema" in body:
            return httpx.Response(200, json={"data": {"__schema": {"types": []}}},
                                  request=req)
        if "viewer" in body:
            return httpx.Response(200, json={"data": {"viewer": {"name": "acct_a"}}},
                                  request=req)
        return httpx.Response(400, json={"errors": ["?"]}, request=req)
    if path == "/robots.txt":
        return httpx.Response(200, text="Disallow: /private/\n",
                              headers=[("Content-Type", "text/plain")], request=req)
    if path == "/static/app.js":
        return httpx.Response(200, text=(
            "const p=location.hash.slice(1);"
            "document.getElementById('x').innerHTML=p;"
            'f("/api/v1/orders");f("/api/v1/me");'),
            headers=[("Content-Type", "application/javascript")], request=req)
    if path == "/":
        return httpx.Response(200, text='<a href="/search?q=x">s</a>'
                                        '<a href="/item?id=1">i</a>'
                                        '<a href="/private/x">p</a>'
                                        '<script src="/static/app.js"></script>',
                              headers=hdrs, request=req)
    if path.startswith("/private/"):
        return httpx.Response(200, text="should-not-be-crawled", headers=hdrs,
                              request=req)
    return httpx.Response(404, text="nf", request=req)


def safe_handler(req: httpx.Request) -> httpx.Response:
    """The same app, PATCHED (false-positive control): active checks MUST
    return zero signals against this handler."""
    path, params = req.url.path, req.url.params
    hdrs: list[tuple[str, str]] = [("Content-Type", "text/html")]
    if path in ("/search", "/render"):
        v = (params.get("q") or params.get("tpl") or "")
        v = (v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
              .replace('"', "&quot;").replace("'", "&#39;"))
        return httpx.Response(200, text=f"<h1>safe: {v}</h1>", headers=hdrs,
                              request=req)
    if path == "/item":
        i = params.get("id", "")
        if "'" in i or '"' in i:
            return httpx.Response(400, text="bad request", headers=hdrs, request=req)
        return httpx.Response(200, text="ORDER list", headers=hdrs, request=req)
    if path.startswith("/api/orders/"):
        who = logged_in(req)
        if not who:
            return httpx.Response(401, text="login", request=req)
        oid = path.rsplit("/", 1)[-1]
        if oid not in ORDERS or ORDERS[oid][1] != who:
            return httpx.Response(403, text="forbidden", request=req)
        name, owner = ORDERS[oid]
        return httpx.Response(200, json={"order": name, "owner": owner}, request=req)
    if path == "/login":
        return handler(req)          # identical login surface
    if path == "/api/whoami":
        # SAFE: only the server-issued exact token validates (no alg:none,
        # no weak re-sign). Signature check in real life; here: equality.
        tok = req.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if tok == JWT:
            return httpx.Response(200, json={"whoami": "acct_a"}, request=req)
        return httpx.Response(401, json={"error": "bad token"}, request=req)
    if path == "/redirect":
        return httpx.Response(302, request=req, headers=[("Location", "/")])
    if path == "/graphql":
        return httpx.Response(400, json={"errors": ["introspection disabled"]},
                              request=req)
    if path == "/static/app.js":
        return httpx.Response(200, text="document.getElementById('x')"
                                        ".textContent = location.hash.slice(1);",
                              headers=[("Content-Type", "application/javascript")],
                              request=req)
    return handler(req)              # everything else identical (robots, home)


def transport(h=None) -> httpx.MockTransport:
    return httpx.MockTransport(h or handler)
