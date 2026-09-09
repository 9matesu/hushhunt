import json
import sqlite3
from pathlib import Path

from hushhunt.sarif import export_sarif

SEV_LEVEL = {"high": "error", "critical": "error", "medium": "warning",
             "low": "note", "informational": "note"}


def _db(tmp_path):
    from hushhunt.db import open_db, upsert_program
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, {"id": "h1:1", "platform": "hackerone", "name": "S",
                          "url": "", "safe_harbor": "all", "max_bounty": 1,
                          "avg_resolution_h": 0, "created_at_remote": None,
                          "policy_text": "", "scope_json": "{}"})
    sid = conn.execute("INSERT INTO signals(program_id,asset,check_id,wstg,"
                       "severity_hint,payload_json,evidence_dir,created_at) "
                       "VALUES('h1:1','https://app.smallco.io/x','xss_reflected',"
                       "'WSTG-INPV-01','medium','{}','ev','now') RETURNING id"
                       ).fetchone()["id"]
    conn.execute("INSERT INTO findings(id,signal_id,stage,confidence,detail_json,"
                 "report_path,updated_at) VALUES(1,?,'reported',0.9,?, 'out/r.md',"
                 "'now')", (sid, json.dumps({"title": "Reflected XSS",
                                             "severity": "medium",
                                             "cvss": "CVSS:3.1/AV:N",
                                             "cwe": "CWE-79"})))
    conn.commit()
    return conn


def test_export_structure(tmp_path):
    conn = _db(tmp_path)
    cfg = type("C", (), {"root": tmp_path})()
    path = export_sarif(conn, cfg)
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "hushhunt"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "xss_reflected" in rule_ids
    res = run["results"][0]
    assert res["ruleId"] == "xss_reflected"
    assert res["level"] == "warning"
    assert "Reflected XSS" in res["message"]["text"]
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] \
        == "https://app.smallco.io/x"
    # CWE carried as tag
    assert res.get("properties", {}).get("tags") == ["CWE-79", "CVSS:3.1/AV:N"]


def test_dropped_findings_excluded(tmp_path):
    conn = _db(tmp_path)
    conn.execute("UPDATE findings SET stage='dropped' WHERE id=1")
    conn.commit()
    cfg = type("C", (), {"root": tmp_path})()
    doc = json.loads(Path(export_sarif(conn, cfg)).read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"] == []
