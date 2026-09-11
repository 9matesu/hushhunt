import json
from hushhunt.db import open_db
from hushhunt.metaharness import append_loop_journal, export_hermes_findings


def test_export_hermes_findings_writes_json(tmp_path):
    conn = open_db(tmp_path / "t.db")
    conn.execute("INSERT INTO programs(id,platform,name,url) VALUES('h1:1','h1','p','http://x')")
    conn.execute("INSERT INTO signals(id,program_id,asset,check_id) VALUES(1,'h1:1','http://x','xss')")
    conn.execute("INSERT INTO findings(id,signal_id,stage,confidence,detail_json) VALUES(1,1,'verified',0.9,'{}')")
    conn.commit()
    out = export_hermes_findings(conn, tmp_path / "out", min_confidence=0.5)
    assert out.exists()
    payload = json.loads(out.read_text())
    assert payload["count"] == 1
    assert payload["findings"][0]["check_id"] == "xss"


def test_append_loop_journal_appends(tmp_path):
    var_dir = tmp_path / "var"
    append_loop_journal(var_dir, "ai_decision", {"action": "probe_ssh", "target": "10.0.0.1"})
    jpath = var_dir / "metaharness_loop.jsonl"
    assert jpath.exists()
    assert "probe_ssh" in jpath.read_text()
