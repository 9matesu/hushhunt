import json
from pathlib import Path

from hushhunt.config import Config
from hushhunt.push import push_finding

PROGRAM = {"id": "h1:1", "name": "SmallCo", "platform": "hackerone",
           "safe_harbor": "all", "url": "https://hackerone.com/smallco"}


def _cfg(tmp_path, mode):
    return Config({"submit": {"mode": mode}, "triage": {"min_confidence": 0.75}}, tmp_path)


def _finding(conf=0.95):
    return {"id": 7, "confidence": conf, "report_path": "out/reports/r7.md",
            "detail_json": json.dumps({"title": "CORS thing", "severity": "medium"})}


def test_draft_mode_queues_for_human(tmp_path):
    cfg = _cfg(tmp_path, "draft")
    path = push_finding(None, cfg, _finding(), PROGRAM)
    assert Path(path).name == "PENDING.md"
    assert "SmallCo: CORS thing" in Path(path).read_text(encoding="utf-8")


def test_auto_blocks_low_confidence(tmp_path):
    cfg = _cfg(tmp_path, "auto")
    result = push_finding(None, cfg, _finding(conf=0.8), PROGRAM)
    assert result == "blocked:below_auto_threshold"
    assert not list((tmp_path / "out").glob("submit_payload_*"))


def test_auto_blocks_no_safe_harbor(tmp_path):
    cfg = _cfg(tmp_path, "auto")
    result = push_finding(None, cfg, _finding(conf=0.95),
                          {**PROGRAM, "safe_harbor": "none"})
    assert result == "blocked:no_safe_harbor"


def test_auto_writes_structured_payload(tmp_path):
    from hushhunt.db import open_db
    conn = open_db(tmp_path / "t.db")
    conn.execute("INSERT INTO findings(id,signal_id,stage,confidence,report_path,"
                 "detail_json,updated_at) VALUES(7,1,'reported',0.95,'r.md','{}','now')")
    conn.commit()
    cfg = _cfg(tmp_path, "auto")
    path = push_finding(conn, cfg, _finding(conf=0.95), PROGRAM)
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    assert payload["program_id"] == "h1:1" and payload["title"] == "CORS thing"
    # no HTTP was made: push only writes files (draft and auto alike)
