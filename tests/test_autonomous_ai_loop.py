import json
from pathlib import Path
import pytest

from hushhunt.config import Config
from hushhunt.db import open_db, upsert_program
from hushhunt.grants import create_grant
from hushhunt.pipeline import active_probe_planned
from hushhunt.planner import PlannedTest
from hushhunt.triage.llm import FakeLlm


@pytest.fixture(autouse=True)
def _grant_secret(monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "testsecret12345678901234567890")


def _setup(tmp_path):
    conn = open_db(tmp_path / "test.db")
    prog = {
        "id": "h1:auto",
        "platform": "hackerone",
        "name": "AutoTest",
        "url": "https://t.invalid",
        "safe_harbor": "all",
        "max_bounty": 1000,
        "avg_resolution_h": 24,
        "created_at_remote": None,
        "policy_text": "",
        "scope_json": json.dumps({"includes": ["t.invalid"], "excludes": []}),
    }
    upsert_program(conn, prog)
    conn.execute("UPDATE programs SET risk_cap='high'")
    create_grant(conn, "h1:auto", "xss_reflected", "probe", 24, 100)
    conn.commit()
    prog = {**prog, "includes": ["t.invalid"], "excludes": [],
            "risk_cap": "high", "policy_text": ""}
    cfg = Config.load("I:/hushhunt")
    cfg.root = tmp_path
    return cfg, conn, prog


def test_active_probe_planned_executes_target(tmp_path):
    import httpx
    cfg, conn, prog = _setup(tmp_path)

    # Mock transport reflecting inert markers
    def handler(request: httpx.Request):
        url = str(request.url)
        if "hush" in url:
            marker = url.split("q=")[-1]
            import urllib.parse
            marker = urllib.parse.unquote(marker)
            return httpx.Response(200, text=f"Found: {marker}")
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(handler)

    planned = [
        PlannedTest(
            module="xss_reflected",
            url="https://t.invalid/search?q=1",
            param="q",
            why="search endpoint reflection test",
        )
    ]

    new_signals = active_probe_planned(cfg, conn, prog, planned, transport=transport)
    assert new_signals >= 1

    stored = conn.execute("SELECT * FROM signals WHERE program_id=?", (prog["id"],)).fetchall()
    assert len(stored) >= 1
    assert stored[0]["check_id"] == "xss_reflected"


def test_autonomous_planner_pipeline_flow(tmp_path):
    import httpx
    from hushhunt.pipeline import triage_verify_report
    from hushhunt.triage.na_kb import NaKb

    cfg, conn, prog = _setup(tmp_path)

    # 1. Observe a parameter
    conn.execute(
        "INSERT INTO params_seen(program_id, url, param, sample_url, sample_value) "
        "VALUES(?,?,?,?,?)",
        (prog["id"], "/search", "q", "https://t.invalid/search?q=test", "test")
    )
    conn.commit()

    # 2. AI Planner proposes test
    llm = FakeLlm([
        {
            "tests": [
                {
                    "module": "xss_reflected",
                    "url": "https://t.invalid/search?q=test",
                    "param": "q",
                    "why": "high potential for reflection"
                }
            ]
        },
        # Triage response
        {
            "findings": [
                {
                    "signal_ids": [1],
                    "title": "Reflected XSS on search parameter",
                    "severity": "medium",
                    "confidence": 0.95,
                    "reasoning": "Inert marker was reflected without sanitization",
                    "requires_poc": True
                }
            ]
        },
        # PoC synthesizer response
        {
            "poc_script": "r = client.fetch('https://t.invalid/search?q=<b>hush</b>')\nassert '<b>hush</b>' in r.text\nresult['ok'] = True\n"
        }
    ])

    def handler(request: httpx.Request):
        url = str(request.url)
        if "hush" in url:
            import urllib.parse
            marker = urllib.parse.unquote(url.split("q=")[-1])
            return httpx.Response(200, text=f"Search result: {marker}")
        return httpx.Response(200, text="Search")

    transport = httpx.MockTransport(handler)

    from hushhunt.pipeline import _params_seen
    from hushhunt.planner import plan
    params = _params_seen(conn, prog["id"])
    context = {"params_seen": [{"url_path": p["sample_url"], "param": p["param"]} for p in params]}

    planned = plan(cfg, conn, llm, prog, context)
    assert len(planned) == 1

    # Execute targeted tests
    n_hits = active_probe_planned(cfg, conn, prog, planned, transport=transport)
    assert n_hits == 1

    # Triage and report
    na_kb = NaKb([])
    client = transport
    class _C:
        def fetch(self, u, headers=None):
            return httpx.Client(transport=transport).get(u, headers=headers)
        def get(self, u, headers=None):
            return httpx.Client(transport=transport).get(u, headers=headers)

    triaged, verified, reported = triage_verify_report(
        cfg, conn, llm, prog, na_kb, live_fetch=_C().get, poc_client=_C()
    )
    assert triaged == 1
    assert verified == 1
    assert reported == 1

    # Verify report was generated on disk
    reports = list((tmp_path / "out/reports").glob("*.md"))
    assert len(reports) == 1
    content = reports[0].read_text(encoding="utf-8")
    assert "Reflected XSS on search parameter" in content
    assert "PoC Script" in content
    assert "result['ok'] = True" in content

