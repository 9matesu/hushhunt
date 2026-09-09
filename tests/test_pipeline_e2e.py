import json
import re
from pathlib import Path

import httpx
import pytest

from hushhunt.pipeline import run_nightly

CFG_YAML = """
llm: {base_url: "http://llm.invalid/v1", model: "fake", temperature: 0.0}
limits:
  rate_per_second_per_target: 1000
  daily_requests_per_program: 40
  max_requests_per_asset: 12
  request_timeout_seconds: 5
  user_agent: "hushhunt-test"
selection:
  small_target_max_bounty: 1500
  new_program_days: 540
  max_targets_per_night: 6
  min_signals_to_triage: 1
triage: {min_confidence: 0.75}
submit: {mode: "draft"}
platforms:
  hackerone: {enabled: true}
  bugcrowd: {enabled: false}
"""

CANARY = "https://hushhunt-canary.invalid"

TARGET_PAGES = {
    "https://app.smallco.io/": (200, "<html><script src='/a.js'></script>"
                                   "<a href='/dashboard'>d</a></html>",
                                [("Set-Cookie", "sessionid=SECRETVALUE123; Path=/"),
                                 ("Server", "nginx/1.18.0")]),
    "https://app.smallco.io/a.js": (200, 'f("/api/v1/users");k="AKIAXTESTKEY12345678";', []),
    "https://app.smallco.io/.git/config": (200, "[core]\n\tbare = false", []),
    "https://api.smallco.io/": (200, "ok", []),
    "https://bigcorp.com/": (200, "clean", [("Content-Security-Policy",
                                             "default-src 'self'; frame-ancestors 'none'"),
                                            ("Strict-Transport-Security", "max-age=1")]),
}


def _page_for(req: httpx.Request):
    key = str(req.url).split("?")[0]
    status, text, headers = TARGET_PAGES.get(key, (404, "nope", []))
    hdrs = dict(headers)
    if key == "https://app.smallco.io/" and req.headers.get("Origin") == CANARY:
        hdrs["Access-Control-Allow-Origin"] = CANARY      # still broken live
    return httpx.Response(status, text=text, headers=list(hdrs.items()))


@pytest.fixture(autouse=True)
def no_real_tls(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))


class SmartLlm:
    """Regex-extracts signal list from the prompt; accepts only
    exposed_files+secret-leak signals, dismisses the header noise."""
    def __init__(self):
        self.calls = []

    def complete_json(self, system, user):
        self.calls.append((system, user))
        sigs = json.loads(user.split("SIGNALS:\n", 1)[1])
        accept = [s for s in sigs if s["check_id"] in
                  ("exposed_files", "js_secret_leak", "cors_misconfig")]
        findings = [{"signal_ids": [s["signal_id"] for s in accept],
                     "title": "Exposed .git/config on app.smallco.io",
                     "severity": "high", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                     "impact": "Source repository disclosure enables further attacks.",
                     "confidence": 0.92, "reasoning": "git config served publicly",
                     "dedupe_key": "gitconfig-app"}] if accept else []
        return {"findings": findings,
                "dismissed": [{"signal_ids": [s["signal_id"] for s in sigs
                                              if s not in accept],
                               "reason": "NA-PATTERN:header-trivia"}]}


def h1_fixture_factory():
    page = json.loads((Path(__file__).parent / "fixtures" / "h1_programs.json")
                      .read_text(encoding="utf-8"))
    return lambda **kw: httpx.Client(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json=page)), auth=kw.get("auth"))


def ct_factory():
    return lambda **kw: httpx.Client(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json=[
            {"name_value": "api.smallco.io"},
            {"name_value": "blog.smallco.io"}])))     # blog excluded -> must vanish


def test_run_nightly_end_to_end_offline(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_H1_USER", "u")
    monkeypatch.setenv("HH_H1_API_TOKEN", "t")
    (tmp_path / "config.yaml").write_text(CFG_YAML, encoding="utf-8")
    from hushhunt.config import Config
    cfg = Config.load(tmp_path)
    transport = httpx.MockTransport(_page_for)
    llm = SmartLlm()

    line = run_nightly(cfg, llm=llm, client_factory=h1_fixture_factory(),
                       transport=transport, ct_factory=ct_factory())

    m = dict(re.findall(r"(\w+)=(\S+)", line))
    assert m["failed"] == "0"
    assert int(m["signals"]) >= 3
    assert m["verified"] == "1" and m["reports"] == "1"

    # ---- MONEY TEST: every target request was inside ITS OWN program's scope
    import sqlite3
    conn = sqlite3.connect(tmp_path / "var" / "hushhunt.db")
    conn.row_factory = sqlite3.Row
    from hushhunt.scope import url_in_scope
    prog_scope = {r["id"]: json.loads(r["scope_json"])
                  for r in conn.execute("SELECT id, scope_json FROM programs")}
    rows = list(conn.execute("SELECT program_id, url FROM request_log"))
    assert rows, "requests were made"
    for r in rows:
        sc = prog_scope[r["program_id"]]
        assert url_in_scope(r["url"], sc["includes"], sc["excludes"]), r["url"]
    # budget: daily cap 40/program; one program has traffic here
    per = conn.execute("SELECT program_id, COUNT(*) c FROM request_log "
                       "GROUP BY program_id").fetchall()
    for p in per:
        assert p["c"] <= 40
    # excluded host never touched
    assert not [r for r in rows if "blog." in r["url"]]

    # ---- report + human queue exist ----------------------------------------
    reports = list((tmp_path / "out/reports").glob("*.md"))
    assert len(reports) == 1
    body = reports[0].read_text(encoding="utf-8")
    assert body.startswith("**Title:**")
    assert "CVSS:3.1" in body and "Steps To Reproduce" in body
    pending = (tmp_path / "out/PENDING.md").read_text(encoding="utf-8")
    assert "Exposed .git/config" in pending
    # ---- positives-only: header trivia was dismissed, not reported ---------
    assert "missing_csp" not in body
    # no live LLM/HTTP calls happened: smart fake consumed the triage
    assert llm.calls and "smallco" in llm.calls[0][1]


def test_no_safe_harbor_gets_passive_only(tmp_path, monkeypatch):
    """Program with safe_harbor none must receive ONLY the baseline GET
    (active checks like files/cors/js skipped by the risk gate)."""
    monkeypatch.setenv("HH_H1_USER", "u")
    monkeypatch.setenv("HH_H1_API_TOKEN", "t")
    (tmp_path / "config.yaml").write_text(CFG_YAML, encoding="utf-8")
    from hushhunt.config import Config
    cfg = Config.load(tmp_path)
    (tmp_path / "var").mkdir(exist_ok=True)
    conn = __import__("hushhunt.db", fromlist=["open_db"]).open_db(
        tmp_path / "var" / "t.db")
    from hushhunt.db import upsert_program
    upsert_program(conn, {"id": "h1:9", "platform": "hackerone", "name": "NoSH",
                          "url": "", "safe_harbor": "none", "max_bounty": 100,
                          "avg_resolution_h": 0.0, "created_at_remote": None,
                          "policy_text": "", "scope_json": json.dumps(
                              {"includes": ["nosafe.example"], "excludes": []})})
    conn.execute("INSERT INTO assets(program_id,asset_type,identifier,origin) "
                 "VALUES('h1:9','DOMAIN','nosafe.example','program_scope')")
    conn.commit()
    prog = {"id": "h1:9", "name": "NoSH", "safe_harbor": "none",
            "includes": ["nosafe.example"], "excludes": []}
    from hushhunt.pipeline import probe_program
    probe_program(cfg, conn, prog, transport=httpx.MockTransport(
        lambda req: httpx.Response(404, text="x")),
        ct_factory=lambda **kw: httpx.Client(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=[]))))
    urls = [r["url"] for r in conn.execute("SELECT url FROM request_log")]
    assert urls == ["https://nosafe.example/"]   # ONE request, nothing else
