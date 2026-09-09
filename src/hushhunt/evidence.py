from __future__ import annotations

from pathlib import Path

import httpx

MAX_BODY = 64 * 1024


def _req_text(req: httpx.Request) -> str:
    lines = [f"{req.method} {req.url} HTTP/1.1"]
    for k, v in req.headers.items():
        if k.lower() in ("cookie", "authorization"):
            v = v[:12] + "...[redacted]"    # evidence must not carry live creds
        lines.append(f"{k}: {v}")
    text = "\n".join(lines) + "\n"
    body = req.content.decode("utf-8", errors="replace") if req.content else ""
    if body:
        text += "\n" + body[:MAX_BODY]
        if len(body) > MAX_BODY:
            text += "\n...[truncated]"
    return text


def _resp_text(resp: httpx.Response | None, err: Exception | None) -> str:
    if resp is None:
        return f"ERROR: {type(err).__name__}: {err}\n"
    lines = [f"HTTP/1.1 {resp.status_code}"]
    for k, v in resp.headers.items():
        if k.lower() == "set-cookie":
            # redact the VALUE only — attributes (HttpOnly/Secure/SameSite)
            # must survive so passive_headers replay still works
            first, sep, rest = v.partition(";")
            v = first.split("=", 1)[0] + "=...[redacted]" + (sep + rest if sep else "")
        lines.append(f"{k}: {v}")
    body = resp.text[:MAX_BODY]
    if len(resp.text) > MAX_BODY:
        body += "\n...[truncated]"
    return "\n".join(lines) + "\n\n" + body + "\n"


def save_capture(dir: str | Path, request: httpx.Request,
                 response: httpx.Response | None, err: Exception | None) -> str:
    """Write numbered request/response capture files; return the evidence dir."""
    d = Path(dir)
    d.mkdir(parents=True, exist_ok=True)
    n = len(list(d.glob("*_req.http"))) + 1
    (d / f"{n:03d}_req.http").write_text(_req_text(request), encoding="utf-8")
    (d / f"{n:03d}_resp.http").write_text(_resp_text(response, err), encoding="utf-8")
    return str(d)
