import json
import re
from pathlib import Path

import httpx
import pytest

from hushhunt.config import Config
from hushhunt.pipeline import run_nightly

CFG_YAML = """
llm: {base_url: "http://llm.invalid/v1", model: "fake", temperature: 0.0}
limits:
  rate_per_second_per_target: 10000
  daily_requests_per_program: 300
  max_requests_per_asset: 80
  request_timeout_seconds: 5
  user_agent: "hushhunt-v2test"
  active:
    daily_requests_per_program: 120
    burst_rate_per_second: 1000
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
oast: {enabled: false, server: "http://fake.oast"}
"""


@pytest.fixture(autouse=True)
def no_tls(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))


@pytest.fixture(autouse=True)
def clean_vulnapp_state():
    """vulnapp.PROFILE is module-level mutable state; reset per test so a
    mass-assign test's marker field can't pollute later handlers."""
    from tests import vulnapp
    vulnapp.PROFILE.clear()
    yield
    vulnapp.PROFILE.clear()


class VulnTriageLlm:
    """Accepts ALL signals as one finding requiring poc; for the poc prompt
    returns a working reflected-xss PoC script."""
    def __init__(self):
        self.calls = []

    def complete_json(self, system, user):
        self.calls.append((system, user))
        if "poc_script" in system:      # only POC_SYSTEM mentions the key
            return {"poc_script": (
                'r = client.fetch("https://t.invalid/search?q=%3Cb%3Ehushx%3C%2Fb%3E")\n'
                'assert "<b>hushx</b>" in r.text\nresult["ok"] = True\n')}
        m = re.search(r"SIGNALS:\n(.*)$", user, re.S)
        sigs = json.loads(m.group(1))
        ids = [s["signal_id"] for s in sigs]
        return {"findings": [{"signal_ids": ids,
                              "title": "Reflected XSS in /search",
                              "severity": "medium",
                              "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                              "impact": "Attacker JS runs in victim session.",
                              "confidence": 0.9, "reasoning": "param echoes raw",
                              "requires_poc": True,
                              "dedupe_key": "xss-search"}],
                "dismissed": []}


def _program_setup(tmp_path):
    from hushhunt.db import open_db, upsert_program
    conn = open_db(tmp_path / "var" / "hushhunt.db")
    upsert_program(conn, {"id": "h1:v2", "platform": "hackerone",
                          "name": "VulnApp VDP", "url": "https://hackerone.com/vulnapp",
                          "safe_harbor": "all", "max_bounty": 500,
                          "avg_resolution_h": 24.0, "created_at_remote": None,
                          "policy_text": "All t.invalid in scope.", "scope_json":
                          json.dumps({"includes": ["t.invalid"], "excludes": []})})
    conn.execute("INSERT INTO assets(program_id,asset_type,identifier,origin) "
                 "VALUES('h1:v2','DOMAIN','t.invalid','program_scope')")
    conn.execute("UPDATE programs SET risk_cap='medium' WHERE id='h1:v2'")
    conn.commit()
    return conn


def test_v2_e2e_grant_gated_active_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "k")
    (tmp_path / "config.yaml").write_text(CFG_YAML, encoding="utf-8")
    (tmp_path / "var").mkdir(exist_ok=True)
    cfg = Config.load(tmp_path)
    conn = _program_setup(tmp_path)

    # NO GRANTS: active modules must not fire at all
    from tests.vulnapp import handler, transport
    from hushhunt.pipeline import granted_modules, active_probe
    prog = {"id": "h1:v2", "name": "V", "platform": "hackerone",
            "safe_harbor": "all", "max_bounty": 500,
            "includes": ["t.invalid"], "excludes": [], "risk_cap": "medium",
            "policy_text": ""}
    assert granted_modules(conn, cfg, prog) == []
    assert active_probe(cfg, conn, prog, transport=transport(handler)) == 0
    active_urls = [r["url"] for r in conn.execute(
        "SELECT url FROM request_log WHERE kind='active'")]
    assert active_urls == []

    # probe grants -> xss_reflected fires; deep-only idor stays blocked
    from hushhunt.grants import create_grant
    create_grant(conn, "h1:v2", "xss_reflected", "probe", 24, 100)
    create_grant(conn, "h1:v2", "idor", "probe", 24, 100)   # probe scope only
    n = active_probe(cfg, conn, prog, transport=transport(handler))
    checks = {r["check_id"] for r in conn.execute(
        "SELECT check_id FROM signals")}
    assert "xss_reflected" in checks
    assert "idor" not in checks           # probe grant can't run deep module
    # every active request stayed on t.invalid
    for r in conn.execute("SELECT url FROM request_log WHERE kind='active'"):
        assert "t.invalid" in r["url"]

    # full night with triage+poc: report generated with PoC script section
    llm = VulnTriageLlm()
    line = run_nightly(cfg, llm=llm, transport=transport(handler),
                       client_factory=lambda **kw: httpx.Client(
                           transport=httpx.MockTransport(
                               lambda req: httpx.Response(
                                   200, json={"data": [], "links": {"next": None}}))))
    m = dict(re.findall(r"(\w+)=(\S+)", line))
    assert int(m["signals"]) >= 2
    assert m["verified"] == "1" and m["reports"] == "1"
    reports = list((tmp_path / "out/reports").glob("*.md"))
    body = reports[0].read_text(encoding="utf-8")
    assert "## PoC Script (re-runnable, sandboxed)" in body
    assert 'result["ok"] = True' in body
    pending = (tmp_path / "out/PENDING.md").read_text(encoding="utf-8")
    assert "Reflected XSS" in pending


def test_lying_llm_finding_is_dropped(tmp_path, monkeypatch):
    """LLM claims a vuln whose PoC CANNOT reproduce -> positive-only gate
    drops it (the model alone never makes a finding)."""
    monkeypatch.setenv("HH_GRANT_SECRET", "k")
    (tmp_path / "config.yaml").write_text(CFG_YAML, encoding="utf-8")
    (tmp_path / "var").mkdir(exist_ok=True)
    cfg = Config.load(tmp_path)
    conn = _program_setup(tmp_path)
    from tests.vulnapp import handler, transport
    prog = {"id": "h1:v2", "name": "V", "platform": "hackerone",
            "safe_harbor": "all", "max_bounty": 500,
            "includes": ["t.invalid"], "excludes": [], "risk_cap": "medium",
            "policy_text": ""}
    # force a triaged finding for the idor check (POC_REQUIRED), no grant,
    # no poc script -> verify must refuse
    from hushhunt.checks import Ctx
    import hushhunt.checks.active.idor as idormod
    sid = conn.execute("INSERT INTO signals(program_id,asset,check_id,wstg,"
                       "severity_hint,payload_json,evidence_dir,created_at) "
                       "VALUES('h1:v2','https://t.invalid/api/orders/1','idor',"
                       "'WSTG-ATHZ-04','high',?,'','now') RETURNING id",
                       (json.dumps({"victim": "acct_a"}),)).fetchone()["id"]
    conn.execute("INSERT INTO findings(signal_id,stage,confidence,detail_json,"
                 "updated_at) VALUES(?,?,?,?,?)",
                 (sid, "triaged", 0.95,
                  json.dumps({"signal_ids": [sid], "requires_poc": True,
                              "title": "phantom"}), "now"))
    conn.commit()
    from hushhunt.verify import verify_finding
    from hushhunt.checks import CHECK_CATALOG
    f = dict(conn.execute("SELECT * FROM findings WHERE signal_id=?", (sid,)).fetchone())
    f["id"] = conn.execute("SELECT id FROM findings WHERE signal_id=?", (sid,)).fetchone()["id"]
    sig = dict(conn.execute("SELECT * FROM signals WHERE id=?", (sid,)).fetchone())
    stage, outcome = verify_finding(conn, cfg, CHECK_CATALOG, f, [sig])
    assert (stage, outcome) == ("dropped", "poc_not_executed")
