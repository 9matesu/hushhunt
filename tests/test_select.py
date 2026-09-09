import json
from datetime import datetime, timezone, timedelta

from hushhunt.db import open_db, upsert_program, add_signal
from hushhunt.select import pick_targets, target_score
from hushhunt.config import Config

CFG = Config({"limits": {}, "selection": {"small_target_max_bounty": 1500,
                                          "new_program_days": 540,
                                          "max_targets_per_night": 6}}, ".")


def _prog(pid, bounty, created_days_ago, sh="all"):
    iso = (datetime.now(timezone.utc) - timedelta(days=created_days_ago)).isoformat()
    return {"id": pid, "platform": "hackerone", "name": pid, "url": "",
            "safe_harbor": sh, "max_bounty": bounty, "avg_resolution_h": 0.0,
            "created_at_remote": iso, "policy_text": "",
            "scope_json": json.dumps({"includes": ["a.example"], "excludes": []})}


def test_small_young_sh_program_scores_highest():
    small = target_score(dict(max_bounty=500, created_at_remote=(
        datetime.now(timezone.utc) - timedelta(days=10)).isoformat(),
        safe_harbor="all"), {}, CFG)
    big_old = target_score(dict(max_bounty=10000, created_at_remote=(
        datetime.now(timezone.utc) - timedelta(days=2000)).isoformat(),
        safe_harbor="all"), {}, CFG)
    assert small > big_old


def test_no_safe_harbor_cannot_outrank_sh_when_equal():
    sh = target_score(dict(max_bounty=500, created_at_remote=None,
                           safe_harbor="all"), {}, CFG)
    nosh = target_score(dict(max_bounty=500, created_at_remote=None,
                             safe_harbor="none"), {}, CFG)
    assert sh - nosh > 2.5


def test_weights_shift_score():
    base = target_score(dict(max_bounty=500, created_at_remote=None,
                             safe_harbor="all"), {}, CFG)
    good = target_score(dict(max_bounty=500, created_at_remote=None,
                             safe_harbor="all"), {"cors_misconfig": 0.9}, CFG)
    bad = target_score(dict(max_bounty=500, created_at_remote=None, safe_harbor="all"),
                       {"cors_misconfig": 0.1}, CFG)
    assert good > base > bad


def test_pick_targets_respects_k_and_skips_crowded(tmp_path):
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, _prog("h1:good", 500, 10))
    upsert_program(conn, _prog("h1:crowd", 400, 20))
    upsert_program(conn, _prog("h1:big", 9000, 2000))
    sid = add_signal(conn, program_id="h1:crowd", asset="x", check_id="c", wstg="w",
                     severity_hint="low", payload_json="{}", evidence_dir="")
    conn.execute("INSERT INTO findings(signal_id,stage,updated_at) VALUES(?,'verified','t')",
                 (sid,))
    conn.commit()
    picks = pick_targets(conn, CFG, {}, k=5)
    ids = [p["id"] for p in picks]
    assert "h1:crowd" not in ids
    assert ids[0] == "h1:good"
    assert picks[0]["includes"] == ["a.example"]
    assert len(pick_targets(conn, CFG, {}, k=1)) == 1
