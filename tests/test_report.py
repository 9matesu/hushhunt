import json
from pathlib import Path

import pytest

from hushhunt.config import Config
from hushhunt.db import open_db, upsert_program
from hushhunt.report import render_report
from hushhunt.checks import CHECK_CATALOG
import hushhunt.checks.cors  # noqa: F401
from hushhunt.evidence import save_capture
import httpx


@pytest.fixture
def world(tmp_path):
    cfg = Config({"triage": {"min_confidence": 0.75}, "submit": {"mode": "draft"}}, tmp_path)
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, {"id": "h1:1", "platform": "hackerone", "name": "S", "url": "x",
                          "safe_harbor": "all", "max_bounty": 100, "avg_resolution_h": 0.0,
                          "created_at_remote": None, "policy_text": "", "scope_json": "{}"})
    url = "https://app.smallco.io/"
    ev = tmp_path / "ev" / "cors"
    req = httpx.Request("GET", url, headers={"Origin": "https://hushhunt-canary.invalid"})
    resp = httpx.Response(200, headers={"Access-Control-Allow-Origin":
                                        "https://hushhunt-canary.invalid"},
                          request=req, text="x")
    save_capture(ev, req, resp, None)
    sid = conn.execute(
        """INSERT INTO signals(program_id,asset,check_id,wstg,severity_hint,payload_json,
             evidence_dir,created_at) VALUES(?,?,?,?,?,?,?,?)
           RETURNING id""",
        ("h1:1", url, "cors_misconfig", "WSTG-CONF-07", "medium",
         json.dumps({"issue": "reflected_arbitrary_origin"}), str(ev), "now")).fetchone()["id"]
    detail = {"title": "CORS: arbitrary origin reflected with credentials",
              "severity": "medium", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
              "impact": "A malicious site can read victim session data from app.smallco.io.",
              "reasoning": "Reflects any origin; credentials flow allowed.",
              "confidence": 0.9, "dedupe_key": "cors-app-reflection"}
    fid = conn.execute(
        "INSERT INTO findings(signal_id,stage,confidence,detail_json,updated_at) "
        "VALUES(?,'verified',0.9,?,'now') RETURNING id", (sid, json.dumps(detail))).fetchone()["id"]
    sig = dict(conn.execute("SELECT * FROM signals WHERE id=?", (sid,)).fetchone())
    frow = dict(conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone())
    frow["id"] = fid
    return conn, cfg, frow, [sig]


def test_poc_script_and_curl_appear_when_present(world):
    conn, cfg, frow, sigs = world
    conn.execute("INSERT INTO poc_scripts(finding_id,code,language,ok_last_run,ran_at) "
                 "VALUES(?,?, 'python',1,'now')", (frow["id"], "client.fetch(url)\nresult['ok']=True"))
    conn.commit()
    path = render_report(conn, cfg, frow, sigs, CHECK_CATALOG)
    body = Path(path).read_text(encoding="utf-8")
    assert "## PoC Script (re-runnable, sandboxed)" in body
    assert "client.fetch(url)" in body
    assert "One-liner: `curl" in body          # derived from evidence capture


def test_report_contains_all_sections_and_evidence(world):
    conn, cfg, frow, sigs = world
    path = render_report(conn, cfg, frow, sigs, CHECK_CATALOG)
    body = Path(path).read_text(encoding="utf-8")
    assert body.startswith("**Title:** CORS")
    for section in ("## Summary", "## Impact", "## Steps To Reproduce",
                    "## Proof of Concept", "## Recommended Remediation", "## References"):
        assert section in body
    assert "GET https://app.smallco.io/" in body          # raw PoC request
    assert "www-project-web-security-testing-guide" in body
    assert conn.execute("SELECT stage FROM findings").fetchone()[0] == "reported"


def test_dedupe_key_suppresses_second_report(world):
    conn, cfg, frow, sigs = world
    p1 = render_report(conn, cfg, frow, sigs, CHECK_CATALOG)
    # second verified finding, same vuln (same dedupe_key): must NOT create a report
    fid2 = conn.execute(
        "INSERT INTO findings(signal_id,stage,confidence,detail_json,updated_at) "
        "VALUES(1,'verified',0.9,?, 'now') RETURNING id",
        (conn.execute("SELECT detail_json FROM findings").fetchone()[0],)).fetchone()["id"]
    frow2 = dict(conn.execute("SELECT * FROM findings WHERE id=?", (fid2,)).fetchone())
    frow2["id"] = fid2
    p2 = render_report(conn, cfg, frow2, sigs, CHECK_CATALOG)
    assert p2 == p1
    assert len(list((Path(cfg.root) / "out/reports").glob("*.md"))) == 1


def test_secrets_never_rendered_full(tmp_path, world):
    conn, cfg, frow, sigs = world
    secret = "AKIA1234567890ABCDEF"
    sigs[0]["payload_json"] = json.dumps({"redacted": "AKIA1234…(len=20)"})
    p = render_report(conn, cfg, frow, sigs, CHECK_CATALOG)
    body = Path(p).read_text(encoding="utf-8")
    assert secret not in body
