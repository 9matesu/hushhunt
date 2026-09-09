from datetime import datetime, timedelta, timezone

import pytest

from hushhunt.db import open_db
from hushhunt.grants import active_grant, create_grant, revoke_grant, risk_allows


def test_create_requires_secret(tmp_path, monkeypatch):
    monkeypatch.delenv("HH_GRANT_SECRET", raising=False)
    conn = open_db(tmp_path / "t.db")
    with pytest.raises(RuntimeError):
        create_grant(conn, "h1:1", "idor", "deep", 24, 50)


def test_probe_grant_grants_probe_not_deep(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "k")
    conn = open_db(tmp_path / "t.db")
    create_grant(conn, "h1:1", "idor", "probe", 24, 50)
    assert active_grant(conn, "h1:1", "idor", "probe") is not None
    assert active_grant(conn, "h1:1", "idor", "deep") is None      # probe < deep
    assert active_grant(conn, "h1:1", "xss_reflected") is None     # no grant for it


def test_expired_grant_is_none(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "k")
    conn = open_db(tmp_path / "t.db")
    create_grant(conn, "h1:1", "idor", "deep", 1, 50)
    future = datetime.now(timezone.utc) + timedelta(hours=2)
    assert active_grant(conn, "h1:1", "idor", "deep",
                        now=lambda: future) is None


def test_exhausted_request_headroom(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "k")
    conn = open_db(tmp_path / "t.db")
    g = create_grant(conn, "h1:1", "idor", "probe", 24, 2)
    assert active_grant(conn, "h1:1", "idor") is not None
    now = datetime.now(timezone.utc).isoformat()
    for _ in range(2):
        conn.execute("INSERT INTO request_log(program_id,ts,url,method,status,ms,kind) "
                     "VALUES(?,?,?,?,?,?,?)", ("h1:1", now, "u", "POST", 200, 1, "active"))
    conn.commit()
    assert active_grant(conn, "h1:1", "idor") is None   # headroom used up
    assert g > 0


def test_revoke(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "k")
    conn = open_db(tmp_path / "t.db")
    gid = create_grant(conn, "h1:1", "idor", "probe", 24, 50)
    revoke_grant(conn, gid)
    assert active_grant(conn, "h1:1", "idor") is None


def test_risk_cap_matrix():
    assert risk_allows("passive", "passive") is True
    assert risk_allows("passive", "low") is False
    assert risk_allows("low", "low") is True and risk_allows("low", "medium") is False
    assert risk_allows("medium", "high") is False
    assert risk_allows("off", "passive") is False        # off blocks EVERYTHING


def test_migrations_idempotent(tmp_path):
    # v1 tables still exist + new columns present
    conn = open_db(tmp_path / "t.db")
    conn2 = open_db(tmp_path / "t.db")   # second open runs migrate again: must not raise
    cols = {r[1] for r in conn.execute("PRAGMA table_info(request_log)")}
    assert "kind" in cols
    pcols = {r[1] for r in conn.execute("PRAGMA table_info(programs)")}
    assert "risk_cap" in pcols
    assert conn2.execute("SELECT COUNT(*) c FROM grants").fetchone()["c"] == 0
