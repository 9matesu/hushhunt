import json
import urllib.request
from hushhunt.dashboard import query_summary, run_server
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


def test_api_summary_serves_json(tmp_path):
    import threading
    conn = open_db(tmp_path / "s.db")
    conn.execute("INSERT INTO programs(id,platform,name,url) VALUES('p1','h1','P1','http://x/')")
    conn.commit()
    srv, port = run_server(str(tmp_path / "s.db"), log_path=None, port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/summary", timeout=5) as r:
            body = json.load(r)
        assert body["total_requests"] == 0
        assert "by_check" in body
    finally:
        srv.shutdown()
        srv.server_close()
