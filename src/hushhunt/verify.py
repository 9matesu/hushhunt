from __future__ import annotations

import json
import re
from pathlib import Path

import httpx

from .checks import Ctx

# Checks whose signals can disappear or change server-side: a live re-fetch
# through the HardenedClient is mandatory before anything is called a
# positive. Replaying stale evidence alone would let a since-fixed endpoint
# slip into a report (false positive => account reputation damage).
LIVE_CONFIRM_REQUIRED = {"exposed_files", "cors_misconfig", "js_secret_leak"}

_STATUS_RE = re.compile(r"^HTTP/1\.1 (\d+)")
_HEADER_RE = re.compile(r"^([A-Za-z0-9\-]+):\s*(.*)$")


def _load_capture(evidence_dir: str) -> httpx.Response | None:
    """Rebuild an httpx.Response (with its request URL) from a stored
    NNN_req.http / NNN_resp.http capture written by evidence.save_capture."""
    d = Path(evidence_dir)
    if not d.is_dir():
        return None
    req_files = sorted(d.glob("*_req.http"))
    resp_files = sorted(d.glob("*_resp.http"))
    if not resp_files or not req_files:
        return None
    first = req_files[0].read_text(encoding="utf-8").splitlines()[0]
    parts = first.split()
    url = parts[1] if len(parts) >= 2 else ""
    lines = resp_files[0].read_text(encoding="utf-8", errors="replace").splitlines()
    m = _STATUS_RE.match(lines[0]) if lines else None
    status = int(m.group(1)) if m else 0
    headers: list[tuple[str, str]] = []
    body: list[str] = []
    in_body = False
    for ln in lines[1:]:
        if in_body:
            body.append(ln)
        elif ln == "":
            in_body = True
        else:
            hm = _HEADER_RE.match(ln)
            if hm:
                headers.append((hm.group(1), hm.group(2)))
    return httpx.Response(status, headers=headers,
                          request=httpx.Request("GET", url), text="\n".join(body))


def _identity_key(check_id: str, payload: dict) -> tuple:
    """What must be identical between original signal and reproduction.
    For live checks only the structural part (path/issue/kind) — server
    content may have changed without invalidating the vulnerability."""
    if check_id == "exposed_files":
        return (payload.get("path"),)
    if check_id == "cors_misconfig":
        return (payload.get("issue"),)
    if check_id == "js_secret_leak":
        return (payload.get("kind"), payload.get("redacted", "")[:8])
    return (json.dumps(payload, sort_keys=True),)


def _reproduce(signal: dict, replay_resp: httpx.Response, live, catalog) -> bool:
    check = catalog[signal["check_id"]]
    want = json.loads(signal["payload_json"])
    if signal["check_id"] in LIVE_CONFIRM_REQUIRED:
        ctx = Ctx(resp=replay_resp, fetch=live)
        if signal["check_id"] == "js_secret_leak":
            je = catalog.get("js_endpoints")
            if je and je.fn:
                je.fn(ctx)  # populates ctx.fetched_js from LIVE script bodies
        regen = check.fn(ctx)
    else:
        regen = check.fn(Ctx(resp=replay_resp, fetch=None))
    return any(r.get("check_id") == signal["check_id"] and
               _identity_key(signal["check_id"], r.get("payload", {})) ==
               _identity_key(signal["check_id"], want)
               for r in regen)


def make_live_replay(signal: dict, fetch):
    """A budget-strict fetch shim: only URLs structurally implied by the
    original signal pass through to the live client; every other candidate
    path is answered with a synthetic 404 (zero traffic). Keeps a verify pass
    to 1 request for exposed_files (the signaling path only), 1 for CORS,
    <=4 for JS."""
    want_path = None
    if signal["check_id"] == "exposed_files":
        want_path = json.loads(signal["payload_json"]).get("path")

    def live(url, headers=None):
        if want_path and not str(url).endswith(want_path):
            return httpx.Response(404, text="not refetched",
                                  request=httpx.Request("GET", url))
        return fetch(url, headers=headers)
    return live


def verify_finding(conn, cfg, catalog, finding: dict, signals: list[dict],
                   live_fetch=None) -> tuple[str, str | None]:
    """Positive-only gate — no LLM. 'verified' requires EVERY backing signal to
    reproduce: deterministic replay over stored evidence for passive checks,
    plus a fresh budgeted re-fetch for volatile ones. Any miss => 'dropped'
    with a machine-readable outcome that feeds the learning loop."""
    if (finding.get("confidence") or 0) < cfg["triage.min_confidence"]:
        return "dropped", "confidence_below_min"
    for s in signals:
        if s["check_id"] not in catalog or catalog[s["check_id"]].fn is None:
            return "dropped", f"unknown_check:{s['check_id']}"
        replayed = _load_capture(s["evidence_dir"]) if s["evidence_dir"] else None
        if replayed is None:
            return "dropped", "missing_evidence"
        live = None
        if s["check_id"] in LIVE_CONFIRM_REQUIRED:
            if live_fetch is None:
                return "dropped", "no_live_channel"
            live = make_live_replay(s, live_fetch)
        try:
            ok = _reproduce(s, replayed, live, catalog)
        except Exception as e:
            return "dropped", f"replay_error:{type(e).__name__}"
        if not ok:
            return "dropped", "replay_miss"
    return "verified", None
