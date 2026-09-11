import json
import urllib.request
import threading
from hushhunt.dashboard import (
    query_summary,
    query_programs,
    query_signals_categorized,
    query_traffic_stats,
    query_verified_findings,
    run_server,
)
from hushhunt.db import open_db


def test_query_summary_counts(tmp_path):
    conn = open_db(tmp_path / "t.db")
    conn.execute("INSERT INTO programs(id,platform,name,url) VALUES('p1','h1','P1','http://x/')")
    conn.execute("INSERT INTO request_log(program_id,ts,url,method,status,ms) VALUES('p1','t','http://x/','GET',200,1)")
    conn.execute("INSERT INTO signals(program_id,asset,check_id,payload_json) VALUES('p1','http://x/','cors_misconfig','{}')")
    conn.commit()
    ro = query_summary(str(tmp_path / "t.db"))
    assert ro["total_requests"] == 1
    assert ro["total_signals"] == 1
    assert ro["by_check"] == {"cors_misconfig": 1}


def test_query_programs_includes_scope_and_bounty(tmp_path):
    conn = open_db(tmp_path / "p.db")
    conn.execute(
        "INSERT INTO programs(id,platform,name,url,max_bounty,scope_json) "
        "VALUES('h1:test','h1','Test Program','http://x/',1000,?)",
        (json.dumps({"includes": ["api.test.com", "*.test.com"]}),)
    )
    conn.execute(
        "INSERT INTO request_log(program_id,ts,url,method,status,ms) "
        "VALUES('h1:test','2026-09-11T12:00:00','http://api.test.com/','GET',200,50)"
    )
    conn.commit()
    
    progs = query_programs(str(tmp_path / "p.db"))
    assert len(progs) == 1
    assert progs[0]["id"] == "h1:test"
    assert progs[0]["max_bounty"] == 1000
    assert "api.test.com" in progs[0]["includes"]
    assert progs[0]["request_count"] == 1


def test_query_signals_categorizes_good_vs_bad(tmp_path):
    conn = open_db(tmp_path / "sig.db")
    # Bad info (noise)
    conn.execute(
        "INSERT INTO signals(id,program_id,asset,check_id,severity_hint,payload_json) "
        "VALUES(1,'p1','https://a/','passive_headers','info','{}')"
    )
    # Good info (actionable potential bug)
    conn.execute(
        "INSERT INTO signals(id,program_id,asset,check_id,severity_hint,payload_json) "
        "VALUES(2,'p1','https://a/','cors_misconfig','medium','{\"acac\":\"true\"}')"
    )
    conn.commit()

    data = query_signals_categorized(str(tmp_path / "sig.db"))
    assert len(data["actionable"]) == 1
    assert data["actionable"][0]["check_id"] == "cors_misconfig"
    assert len(data["noise"]) == 1
    assert data["noise"][0]["check_id"] == "passive_headers"


def test_query_traffic_stats(tmp_path):
    conn = open_db(tmp_path / "tr.db")
    for st in (200, 200, 404, 403, 500):
        conn.execute(
            "INSERT INTO request_log(program_id,ts,url,method,status,ms) "
            f"VALUES('p1','2026-09-11T12:00:00','http://x/','GET',{st},10)"
        )
    conn.commit()

    stats = query_traffic_stats(str(tmp_path / "tr.db"))
    assert stats["status_codes"][200] == 2
    assert stats["status_codes"][404] == 1
    assert stats["status_codes"][500] == 1


def test_query_verified_findings_with_report(tmp_path):
    conn = open_db(tmp_path / "v.db")
    report_file = tmp_path / "rep1.md"
    report_file.write_text("**Title:** XSS on test\n## PoC\nalert(1)")
    conn.execute(
        "INSERT INTO signals(id,program_id,asset,check_id,severity_hint) "
        "VALUES(10,'target:app','https://app.test/vuln','xss_reflected','high')"
    )
    conn.execute(
        "INSERT INTO findings(id,signal_id,stage,confidence,report_path,updated_at) "
        "VALUES(1,10,'verified',0.95,?, '2026-09-11T14:00:00')",
        (str(report_file),)
    )
    conn.commit()

    findings = query_verified_findings(str(tmp_path / "v.db"))
    assert len(findings) == 1
    assert findings[0]["stage"] == "verified"
    assert findings[0]["program_id"] == "target:app"
    assert findings[0]["check_id"] == "xss_reflected"
    assert "alert(1)" in findings[0]["report_text"]


def test_api_routes_serve_json(tmp_path):
    conn = open_db(tmp_path / "s.db")
    conn.execute("INSERT INTO programs(id,platform,name,url) VALUES('p1','h1','P1','http://x/')")
    conn.commit()
    srv, port = run_server(str(tmp_path / "s.db"), log_path=None, port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        for ep in ("/api/summary", "/api/programs", "/api/signals", "/api/traffic", "/api/recent", "/api/verified"):
            with urllib.request.urlopen(f"http://127.0.0.1:{port}{ep}", timeout=5) as r:
                assert r.status == 200
                data = json.load(r)
                assert isinstance(data, (dict, list))
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            assert r.status == 200
            content = r.read().decode("utf-8")
            assert "<!doctype html>" in content.lower()
    finally:
        srv.shutdown()
        srv.server_close()
