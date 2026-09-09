import json
from datetime import datetime, timezone

import pytest

from hushhunt.db import open_db, upsert_program
from hushhunt.__main__ import main


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "k")


def _world(tmp_path, policy="", cap="medium"):
    (tmp_path / "config.yaml").write_text(
        "triage: {min_confidence: 0.75}\n", encoding="utf-8")
    (tmp_path / "var").mkdir(exist_ok=True)
    conn = open_db(tmp_path / "var" / "hushhunt.db")
    upsert_program(conn, {"id": "h1:5", "platform": "hackerone", "name": "P",
                          "url": "", "safe_harbor": "all", "max_bounty": 100,
                          "avg_resolution_h": 0, "created_at_remote": None,
                          "policy_text": policy,
                          "scope_json": '{"includes":["a.io"],"excludes":[]}'})
    conn.execute("UPDATE programs SET risk_cap=?", (cap,))
    conn.commit()
    conn.close()
    return tmp_path


def test_grant_cli_ok(tmp_path, capsys):
    root = _world(tmp_path)
    rc = main(["grant", "--root", str(root), "--program", "h1:5",
               "--module", "xss_reflected", "--scope", "probe"])
    assert rc == 0
    assert "GRANT #1" in capsys.readouterr().out


def test_grant_cli_refused_by_policy(tmp_path, capsys):
    root = _world(tmp_path, policy="Do not run any timing based SQL attacks.")
    rc = main(["grant", "--root", str(root), "--program", "h1:5",
               "--module", "sqli_boolean", "--scope", "deep"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "REFUSED" in out and "timing" in out.lower()


def test_grant_cli_unknown_program(tmp_path, capsys):
    root = _world(tmp_path)
    rc = main(["grant", "--root", str(root), "--program", "h1:NOPE",
               "--module", "ssti"])
    assert rc == 2
    assert "not synced" in capsys.readouterr().out


def test_revoke_cli(tmp_path, capsys):
    root = _world(tmp_path)
    main(["grant", "--root", str(root), "--program", "h1:5",
          "--module", "ssti"])
    rc = main(["revoke", "--root", str(root), "1"])
    assert rc == 0
    conn = open_db(root / "var" / "hushhunt.db")
    assert conn.execute("SELECT COUNT(*) c FROM grants").fetchone()["c"] == 0


def test_status_cli_lists_grants(tmp_path, capsys):
    root = _world(tmp_path)
    main(["grant", "--root", str(root), "--program", "h1:5",
          "--module", "idor", "--scope", "deep"])
    rc = main(["status", "--root", str(root)])
    out = capsys.readouterr().out
    assert rc == 0 and "idor" in out and "deep" in out
