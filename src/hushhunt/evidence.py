from __future__ import annotations

from pathlib import Path

import httpx

MAX_BODY = 64 * 1024


def _req_text(req: httpx.Request) -> str:
    lines = [f"{req.method} {req.url} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in req.headers.items()]
    return "\n".join(lines) + "\n"


def _resp_text(resp: httpx.Response | None, err: Exception | None) -> str:
    if resp is None:
        return f"ERROR: {type(err).__name__}: {err}\n"
    lines = [f"HTTP/1.1 {resp.status_code}"]
    lines += [f"{k}: {v}" for k, v in resp.headers.items()]
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
