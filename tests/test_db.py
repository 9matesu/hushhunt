from datetime import datetime, timezone

from hushhunt.db import (open_db, upsert_program, add_asset, add_signal,
                         count_requests_today, log_request, bump_weight,
                         get_weights, set_stage, save_playbook, load_playbook)


def _program(pid="h1:1"):
    return {"id": pid, "platform": "hackerone", "name": "SmallCo", "url": "https://h1/x",
            "safe_harbor": "all", "max_bounty": 500, "avg_resolution_h": 48.0,
            "created_at_remote": "2025-01-01T00:00:00Z", "policy_text": "p",
            "scope_json": '{"includes":["*.smallco.io"],"excludes":[]}'}


def test_program_upsert_idempotent(tmp_path):
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, _program())
    upsert_program(conn, {**_program(), "max_bounty": 700})
    row = conn.execute("SELECT max_bounty FROM programs").fetchone()
    assert row["max_bounty"] == 700
    assert conn.execute("SELECT COUNT(*) c FROM programs").fetchone()["c"] == 1


def test_asset_dedupe(tmp_path):
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, _program())
    assert add_asset(conn, "h1:1", "WILDCARD", "*.smallco.io", "program_scope") is True
    assert add_asset(conn, "h1:1", "WILDCARD", "*.smallco.io", "program_scope") is False
    assert add_asset(conn, "h1:1", "DOMAIN", "api.smallco.io", "ct_log") is True


def test_signal_dedupe(tmp_path):
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, _program())
    sig = dict(program_id="h1:1", asset="https://app.smallco.io", check_id="cors_misconfig",
               wstg="WSTG-CONF-07", severity_hint="medium", payload_json='{"origin":"x"}',
               evidence_dir="var/evidence/a")
    id1 = add_signal(conn, **sig)
    assert isinstance(id1, int)
    assert add_signal(conn, **sig) is None


def test_request_budget_counting(tmp_path):
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, _program())
    today = datetime.now(timezone.utc).isoformat()
    log_request(conn, "h1:1", today, "https://a/smallco.io/x", "GET", 200, 10)
    log_request(conn, "h1:1", "2000-01-01T00:00:00", "https://a/smallco.io/y", "GET", 200, 10)
    assert count_requests_today(conn, "h1:1") == 1


def test_weight_ewma(tmp_path):
    conn = open_db(tmp_path / "t.db")
    bump_weight(conn, "cors_misconfig", accepted=True)
    assert get_weights(conn)["cors_misconfig"] == 0.6
    bump_weight(conn, "cors_misconfig", accepted=False)
    assert round(get_weights(conn)["cors_misconfig"], 6) == 0.48


def test_stage_and_playbook(tmp_path):
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, _program())
    sid = add_signal(conn, program_id="h1:1", asset="a", check_id="c", wstg="w",
                     severity_hint="low", payload_json="{}", evidence_dir="")
    import sqlite3
    conn.execute("INSERT INTO findings(signal_id,stage,confidence,updated_at) VALUES(?,'triaged',0.8,?)",
                 (sid, datetime.now(timezone.utc).isoformat()))
    fid = conn.execute("SELECT id FROM findings").fetchone()["id"]
    set_stage(conn, fid, "verified", confidence=0.9)
    row = conn.execute("SELECT stage, confidence FROM findings WHERE id=?", (fid,)).fetchone()
    assert (row["stage"], row["confidence"]) == ("verified", 0.9)
    assert load_playbook(conn) is None
    save_playbook(conn, "rules v1")
    assert load_playbook(conn)["text"] == "rules v1"
    save_playbook(conn, "rules v2")
    assert load_playbook(conn)["version"] == 2
