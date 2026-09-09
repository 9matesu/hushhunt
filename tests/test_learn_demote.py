from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hushhunt.config import Config
from hushhunt.db import add_signal, get_weights, open_db, upsert_program
from hushhunt.learn import auto_demote, demoted_modules, record_outcome, undemote

CFG = Config({"triage": {"min_confidence": 0.75}}, ".")


def _world(tmp_path):
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, {"id": "h1:1", "platform": "hackerone", "name": "S",
                          "url": "", "safe_harbor": "all", "max_bounty": 1,
                          "avg_resolution_h": 0, "created_at_remote": None,
                          "policy_text": "", "scope_json": "{}"})
    fids = []
    for i in range(5):
        sid = add_signal(conn, program_id="h1:1", asset=f"a{i}",
                         check_id="ssti", wstg="w", severity_hint="low",
                         payload_json="{}", evidence_dir="")
        fids.append(conn.execute(
            "INSERT INTO findings(signal_id,stage,confidence,updated_at) "
            "VALUES(?,'reported',0.9,'now') RETURNING id", (sid,)).fetchone()["id"])
    return conn, fids


def test_demotion_after_4_na(tmp_path):
    conn, fids = _world(tmp_path)
    assert demoted_modules(conn) == set()
    for fid in fids[:4]:
        record_outcome(conn, CFG, fid, "ssti", "not-applicable")
    demoted = auto_demote(conn, cfg=CFG)
    assert "ssti" in demoted
    assert "ssti" in demoted_modules(conn)
    # 4 NA in a row at EWMA 0.8 => precision 0.5*0.8^4 ≈ 0.205 < 0.25


def test_not_demoted_without_sample_size(tmp_path):
    conn, fids = _world(tmp_path)
    record_outcome(conn, CFG, fids[0], "blind_oast", "not-applicable")
    record_outcome(conn, CFG, fids[1], "blind_oast", "resolved")
    assert "blind_oast" not in demoted_modules(conn)
    assert auto_demote(conn, cfg=CFG) == []     # n=2 < 4


def test_undemote_clears(tmp_path):
    conn, fids = _world(tmp_path)
    for fid in fids[:4]:
        record_outcome(conn, CFG, fid, "ssti", "not-applicable")
    auto_demote(conn, cfg=CFG)
    undemote(conn, "ssti")
    assert "ssti" not in demoted_modules(conn)


def test_rescue_prevents_demotion(tmp_path):
    conn, fids = _world(tmp_path)
    for fid in fids[:4]:
        record_outcome(conn, CFG, fid, "ssti", "not-applicable")
    record_outcome(conn, CFG, fids[4], "ssti", "resolved")   # 5th accepted
    auto_demote(conn, cfg=CFG)
    assert "ssti" not in demoted_modules(conn)               # precision rescued
