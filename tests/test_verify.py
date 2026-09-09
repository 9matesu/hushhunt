import json
from pathlib import Path

import httpx

from hushhunt.checks import CHECK_CATALOG, Ctx
import hushhunt.checks.files        # noqa: F401
import hushhunt.checks.cors         # noqa: F401
import hushhunt.checks.headers      # noqa: F401
import hushhunt.checks.jsmining     # noqa: F401
from hushhunt.config import Config
from hushhunt.evidence import save_capture
from hushhunt.verify import verify_finding

CFG = Config({"triage": {"min_confidence": 0.75}}, ".")


def _capture(tmp_path, name, url, status, headers, text):
    d = tmp_path / "ev" / name
    req = httpx.Request("GET", url)
    resp = httpx.Response(status, headers=headers, request=req, text=text)
    save_capture(d, req, resp, None)
    return str(d)


def _cors_signal(tmp_path):
    url = "https://app.smallco.io/"
    canary = "https://hushhunt-canary.invalid"
    ev = _capture(tmp_path, "cors", url, 200,
                  {"Access-Control-Allow-Origin": canary}, "hi")
    sig = {"check_id": "cors_misconfig", "asset": url, "severity_hint": "medium",
           "payload_json": json.dumps({"issue": "reflected_arbitrary_origin",
                                       "acao": canary, "acac": ""}),
           "evidence_dir": ev}
    return sig


def test_cors_verified_when_live_still_echoes(tmp_path):
    sig = _cors_signal(tmp_path)

    def live(url, headers=None):
        return httpx.Response(200, headers={"Access-Control-Allow-Origin":
                                            "https://hushhunt-canary.invalid"},
                              request=httpx.Request("GET", url), text="ok")
    stage, outcome = verify_finding(None, CFG, CHECK_CATALOG,
                                    {"confidence": 0.9}, [sig], live_fetch=live)
    assert (stage, outcome) == ("verified", None)


def test_cors_dropped_when_fixed_since_scan(tmp_path):
    sig = _cors_signal(tmp_path)

    def live(url, headers=None):
        return httpx.Response(200, headers={}, request=httpx.Request("GET", url),
                              text="patched")
    stage, outcome = verify_finding(None, CFG, CHECK_CATALOG,
                                    {"confidence": 0.9}, [sig], live_fetch=live)
    assert (stage, outcome) == ("dropped", "replay_miss")


def test_passive_headers_verify_without_live(tmp_path):
    url = "https://app.smallco.io/dash"
    ev = _capture(tmp_path, "hdr", url, 200,
                  [("Server", "nginx/1.18.0")], "page")
    payload = {"header": "server", "value": "nginx/1.18.0"}
    sig = {"check_id": "version_disclosure", "asset": url, "severity_hint": "informational",
           "payload_json": json.dumps(payload), "evidence_dir": ev}
    stage, _ = verify_finding(None, CFG, CHECK_CATALOG, {"confidence": 0.8}, [sig],
                              live_fetch=None)
    assert stage == "verified"   # deterministic replay is enough for passive checks


def test_missing_evidence_drops(tmp_path):
    sig = {"check_id": "version_disclosure", "asset": "x", "severity_hint": "low",
           "payload_json": "{}", "evidence_dir": str(tmp_path / "nothing")}
    stage, outcome = verify_finding(None, CFG, CHECK_CATALOG, {"confidence": 0.9},
                                    [sig], live_fetch=lambda u: None)
    assert (stage, outcome) == ("dropped", "missing_evidence")


def test_confidence_boundary(tmp_path):
    sig = _cors_signal(tmp_path)
    for conf, expected in ((0.74, "dropped"), (0.75, "verified")):
        def live(url, headers=None):
            return httpx.Response(200, headers={
                "Access-Control-Allow-Origin": "https://hushhunt-canary.invalid"},
                request=httpx.Request("GET", url))
        stage, _ = verify_finding(None, CFG, CHECK_CATALOG, {"confidence": conf},
                                  [sig], live_fetch=live)
        assert stage == expected


def test_live_channel_cost_bounded_to_signaling_path(tmp_path):
    """exposed_files verify must refetch ONLY the path the signal flagged,
    even though the check normally probes the whole allowlist."""
    url = "https://app.smallco.io/.git/config"
    body = "[core]\n\trepositoryformatversion = 0"
    ev = _capture(tmp_path, "git", url, 200, {"Content-Type": "text/plain"}, body)
    sig = {"check_id": "exposed_files", "asset": url, "severity_hint": "high",
           "payload_json": json.dumps({"path": "/.git/config", "status": 200,
                                       "preview": body}),
           "evidence_dir": ev}
    calls = []

    def live(u, headers=None):
        calls.append(str(u))
        return httpx.Response(200, text=body, request=httpx.Request("GET", u))
    stage, _ = verify_finding(None, CFG, CHECK_CATALOG, {"confidence": 0.9},
                              [sig], live_fetch=live)
    assert stage == "verified"
    assert calls == [url]  # exactly 1 live request — the low-noise verify contract
