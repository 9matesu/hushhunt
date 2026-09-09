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
LIVE_CONFIRM_REQUIRED = {"exposed_files", "cors_misconfig", "js_secret_leak",
                         "xss_reflected", "ssti", "sqli_error",
                         "open_redirect_chain"}
# Deep findings cannot be replayed from captured evidence alone (they need
# live sessions/OAST) => they must carry an EXECUTED poc_script to verify.
POC_REQUIRED = {"idor", "mass_assign", "jwt_misuse", "graphql_probe",
                "blind_oast", "sqli_boolean", "xss_dom", "js_endpoints",
                "cmd_inject"}

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
    For live/active checks only the structural part (path/issue/kind/param) —
    nonces and previews change every run without invalidating the vuln."""
    if check_id == "exposed_files":
        return (payload.get("path"),)
    if check_id == "cors_misconfig":
        return (payload.get("issue"),)
    if check_id == "js_secret_leak":
        return (payload.get("redacted", "")[:10],)
    if check_id in ("blind_oast", "cmd_inject"):
        return (payload.get("param"), payload.get("syntax", payload.get("param")))
    if check_id in ("xss_reflected", "ssti", "sqli_error", "sqli_boolean",
                    "open_redirect_chain", "mass_assign", "idor"):
        return (payload.get("param") or payload.get("field")
                or payload.get("victim"),)
    if check_id == "graphql_probe":
        return (payload.get("issue"),)
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
        if signal["check_id"] in ("xss_reflected", "ssti", "sqli_error",
                                  "open_redirect_chain"):
            # live re-probe: re-run the check on the ORIGINAL asset surface
            ctx.params = [(want.get("asset") or str(replay_resp.request.url),
                           want["param"], "")]
            regen = check.fn(ctx)
        else:
            regen = check.fn(ctx)
    else:
        ctx = Ctx(resp=replay_resp, fetch=None)
        regen = check.fn(ctx)
    return any(r.get("check_id") == signal["check_id"] and
               _identity_key(signal["check_id"], r.get("payload", {})) ==
               _identity_key(signal["check_id"], want)
               for r in regen)


def make_live_replay(signal: dict, fetch):
    """A budget-strict fetch shim: only URLs structurally implied by the
    original signal pass through to the live client; every other candidate
    path is answered with a synthetic 404 (zero traffic). Keeps a verify pass
    to 1 request for exposed_files (the signaling path only), 1 for CORS,
    <=4 for JS, <=4 GETs on the same path family for active probes."""
    want_path = None
    if signal["check_id"] == "exposed_files":
        want_path = json.loads(signal["payload_json"]).get("path")
    elif signal["check_id"] in LIVE_CONFIRM_REQUIRED:
        from urllib.parse import urlparse
        want_path = urlparse(signal["asset"]).path

    def live(url, headers=None):
        if want_path:
            from urllib.parse import urlparse
            if urlparse(str(url)).path != want_path:
                return httpx.Response(404, text="not refetched",
                                      request=httpx.Request("GET", url))
        return fetch(url, headers=headers)
    return live


def has_ok_poc(conn, finding_id: int) -> bool:
    if conn is None:
        return False
    row = conn.execute(
        "SELECT 1 FROM poc_scripts WHERE finding_id=? AND ok_last_run=1 LIMIT 1",
        (finding_id,)).fetchone()
    return row is not None


def verify_finding(conn, cfg, catalog, finding: dict, signals: list[dict],
                   live_fetch=None, live_recheck=None) -> tuple[str, str | None]:
    """Positive-only gate — no LLM. Passive/live-GET signals must reproduce
    from stored evidence (+1 budgeted re-fetch). Session/OAST signals can't
    be replayed from captures: they verify via an executed PoC script OR a
    live re-check callback (the check itself re-run with fresh sessions).
    Any miss => 'dropped' with a machine-readable outcome for learning."""
    if (finding.get("confidence") or 0) < cfg["triage.min_confidence"]:
        return "dropped", "confidence_below_min"
    for s in signals:
        if s["check_id"] not in catalog or catalog[s["check_id"]].fn is None:
            return "dropped", f"unknown_check:{s['check_id']}"
        if s["check_id"] in POC_REQUIRED:
            if has_ok_poc(conn, finding["id"]):
                continue
            if live_recheck and live_recheck(s):
                continue
            return "dropped", "poc_not_executed"
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
