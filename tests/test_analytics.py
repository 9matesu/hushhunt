import pytest

from hushhunt.db import open_db


def test_compute_analytics_basic(tmp_path):
    from hushhunt.analytics import compute_analytics
    conn = open_db(tmp_path / "test.db")
    conn.execute(
        "INSERT INTO request_log(program_id, ts, url, method, status, ms, kind) "
        "VALUES(?,?,?,?,?,?,?)",
        ("h1:a", "2026-09-10", "https://t.invalid/", "GET", 200, 100, "passive")
    )
    conn.execute(
        "INSERT INTO signals(program_id, asset, check_id, wstg, severity_hint, payload_json) "
        "VALUES(?,?,?,?,?,?)",
        ("h1:a", "https://t.invalid/", "xss_reflected", "WSTG-INPV-01", "medium", '{"a": 1}')
    )
    stats = compute_analytics(conn)
    assert "yield_by_check" in stats
    assert "total_requests" in stats
    assert stats["total_requests"] == 1
    assert "xss_reflected" in stats["yield_by_check"]


def test_compute_analytics_empty_db(tmp_path):
    from hushhunt.analytics import compute_analytics
    conn = open_db(tmp_path / "test.db")
    stats = compute_analytics(conn)
    assert stats["total_requests"] == 0
    assert stats["total_signals"] == 0
    assert stats["total_verified"] == 0


def test_cli_status_analytics(tmp_path, capsys):
    from hushhunt.__main__ import main
    (tmp_path / "var").mkdir(parents=True, exist_ok=True)
    conn = open_db(tmp_path / "var/hushhunt.db")
    conn.execute(
        "INSERT INTO request_log(program_id, ts, url, method, status, ms, kind) "
        "VALUES(?,?,?,?,?,?,?)",
        ("h1:a", "2026-09-10", "https://t.invalid/", "GET", 200, 100, "passive")
    )
    conn.commit()
    rc = main(["status", "--root", str(tmp_path), "--analytics"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "analytics:" in captured.out
    assert "requests=1" in captured.out

