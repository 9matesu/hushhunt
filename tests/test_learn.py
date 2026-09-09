from pathlib import Path

import pytest

from hushhunt.config import Config
from hushhunt.db import add_signal, get_weights, open_db, upsert_program
from hushhunt.learn import find_check_id, propose_playbook_patch, record_outcome

CFG = Config({"triage": {"min_confidence": 0.75}, "submit": {"mode": "draft"}}, ".")


def _world(tmp_path):
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, {"id": "h1:1", "platform": "hackerone", "name": "S", "url": "",
                          "safe_harbor": "all", "max_bounty": 1, "avg_resolution_h": 0,
                          "created_at_remote": None, "policy_text": "", "scope_json": "{}"})
    sid = add_signal(conn, program_id="h1:1", asset="a", check_id="cors_misconfig",
                     wstg="w", severity_hint="medium", payload_json="{}", evidence_dir="")
    fid = conn.execute("INSERT INTO findings(signal_id,stage,confidence,updated_at) "
                       "VALUES(?,'reported',0.9,'now') RETURNING id", (sid,)).fetchone()["id"]
    return conn, fid


def test_resolved_boosts_precision(tmp_path):
    conn, fid = _world(tmp_path)
    w = record_outcome(conn, CFG, fid, "cors_misconfig", "resolved")
    assert w == 0.6
    row = conn.execute("SELECT stage,outcome FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["stage"] == "accepted" and row["outcome"] == "accepted"


def test_na_lowers_precision(tmp_path):
    conn, fid = _world(tmp_path)
    record_outcome(conn, CFG, fid, "cors_misconfig", "not-applicable")
    record_outcome(conn, CFG, fid, "cors_misconfig", "duplicate")
    assert round(get_weights(conn)["cors_misconfig"], 4) == round(0.8 * 0.4 + 0.2 * 0.0, 4)


def test_unknown_state_raises(tmp_path):
    conn, fid = _world(tmp_path)
    with pytest.raises(ValueError):
        record_outcome(conn, CFG, fid, "x", "bounty-confirmed")


def test_find_check_id(tmp_path):
    conn, fid = _world(tmp_path)
    assert find_check_id(conn, fid) == "cors_misconfig"


def test_playbook_patch_written(tmp_path):
    conn, fid = _world(tmp_path)
    record_outcome(conn, CFG, fid, "cors_misconfig", "not-applicable")
    conn.execute("UPDATE findings SET stage='reported', detail_json=? WHERE id=?",
                 ('{"reason":"NA-PATTERN:NA-003","why":"cookie flags alone"}', fid))
    record_outcome(conn, CFG, fid, "passive_headers", "not-applicable")
    cfg = Config({"triage": {"min_confidence": 0.75}}, tmp_path)
    path = propose_playbook_patch(conn, cfg)
    body = Path(path).read_text(encoding="utf-8")
    assert "cors_misconfig" in body and "Lowest-precision" in body
    proposed = json_load(tmp_path / "out/na_kb_proposed.json")
    assert isinstance(proposed, list) and len(proposed) >= 1


def json_load(p):
    import json
    return json.loads(Path(p).read_text(encoding="utf-8"))
