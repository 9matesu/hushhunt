from __future__ import annotations

import re

from . import Ctx, register

_VERSION_RE = re.compile(r"\d+\.\d+")


def _signal(ctx: Ctx, issue: str, detail: str, severity: str) -> dict:
    return {"check_id": "passive_headers", "asset": str(ctx.resp.request.url),
            "severity_hint": severity,
            "payload": {"issue": issue, "detail": detail}}


def _redact(value: str) -> str:
    """Never persist full session tokens — keep a 6-char prefix for triage."""
    return value[:6]


@register("passive_headers", "WSTG-CONF-14", "passive")
def check_headers(ctx: Ctx) -> list[dict]:
    resp = ctx.resp
    out: list[dict] = []
    headers = {k.lower(): v for k, v in resp.headers.items()}
    is_https = str(resp.request.url).startswith("https")

    if "content-security-policy" not in headers:
        out.append(_signal(ctx, "missing_csp",
                           "No Content-Security-Policy header", "informational"))
    if is_https and "strict-transport-security" not in headers:
        out.append(_signal(ctx, "missing_hsts",
                           "No Strict-Transport-Security header on HTTPS origin",
                           "informational"))

    for cookie in resp.headers.get_list("set-cookie"):
        low = cookie.lower()
        name = cookie.split("=", 1)[0].strip()
        value = cookie.split("=", 1)[1].split(";", 1)[0].strip() if "=" in cookie else ""
        looks_session = any(t in name.lower()
                            for t in ("session", "sid", "auth", "token", "jsession"))
        if looks_session and "httponly" not in low:
            out.append(_signal(ctx, "cookie_no_httponly",
                               f"session cookie '{name}' (value {_redact(value)}…) "
                               f"lacks HttpOnly", "medium"))
        if looks_session and is_https and "secure" not in low:
            out.append(_signal(ctx, "cookie_no_secure",
                               f"session cookie '{name}' lacks Secure flag", "medium"))
        if looks_session and "samesite" not in low:
            out.append(_signal(ctx, "cookie_no_samesite",
                               f"session cookie '{name}' lacks SameSite attribute",
                               "low"))

    xfo = headers.get("x-frame-options", "").upper()
    if "frame-ancestors" not in headers.get("content-security-policy", "") and not xfo:
        out.append(_signal(ctx, "missing_clickjacking_protection",
                           "Neither X-Frame-Options nor CSP frame-ancestors set",
                           "informational"))
    return out


@register("version_disclosure", "WSTG-INFO-002", "passive")
def check_version(ctx: Ctx) -> list[dict]:
    resp = ctx.resp
    out = []
    for h in ("server", "x-powered-by", "x-aspnet-version"):
        val = resp.headers.get(h)
        if val and _VERSION_RE.search(val):
            out.append({"check_id": "version_disclosure",
                        "asset": str(resp.request.url), "severity_hint": "informational",
                        "payload": {"header": h, "value": val}})
    return out
