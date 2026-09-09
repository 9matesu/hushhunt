import httpx
import pytest

from hushhunt.config import Config
from hushhunt.db import count_requests_today, open_db, upsert_program
from hushhunt.grants import create_grant
from hushhunt.http import BudgetExceeded, HardenedClient, OutOfScope

PROG = {"id": "h1:1", "name": "S", "includes": ["*.smallco.io"], "excludes": []}


def _hc(tmp_path, handler, active_daily=100):
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, {"id": "h1:1", "platform": "hackerone", "name": "S", "url": "",
                          "safe_harbor": "all", "max_bounty": 1, "avg_resolution_h": 0,
                          "created_at_remote": None, "policy_text": "", "scope_json": "{}"})
    cfg = Config({"limits": {"rate_per_second_per_target": 1000,
                             "daily_requests_per_program": 500,
                             "max_requests_per_asset": 12,
                             "request_timeout_seconds": 5, "user_agent": "t",
                             "active": {"daily_requests_per_program": active_daily,
                                        "burst_rate_per_second": 10}}}, tmp_path)
    hc = HardenedClient(conn, cfg, PROG, transport=httpx.MockTransport(handler))
    return hc, conn


def test_post_without_grant_refused_before_network(tmp_path):
    calls = []
    hc, conn = _hc(tmp_path, lambda r: calls.append(r.url) or httpx.Response(200))
    with pytest.raises(PermissionError):
        hc.post("https://app.smallco.io/api", data={"x": "1"}, grant_id=99)
    assert calls == []
    assert count_requests_today(conn, "h1:1") == 0


def test_post_with_grant_succeeds_and_counts_active(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "k")
    calls = []

    def handler(req):
        calls.append((req.method, str(req.url)))
        return httpx.Response(200, text="ok")
    hc, conn = _hc(tmp_path, handler)
    gid = create_grant(conn, "h1:1", "idor", "probe", 24, 10)
    r = hc.post("https://app.smallco.io/api", data={"x": "1"}, grant_id=gid)
    assert r.status_code == 200
    assert calls == [("POST", "https://app.smallco.io/api")]
    assert count_requests_today(conn, "h1:1", kind="active") == 1
    assert count_requests_today(conn, "h1:1", kind="passive") == 0


def test_grant_scope_exhausted_mid_flight(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "k")
    calls = []
    hc, conn = _hc(tmp_path, lambda r: calls.append(1) or httpx.Response(200),
                   active_daily=100)
    gid = create_grant(conn, "h1:1", "idor", "probe", 24, 2)   # max 2
    hc.post("https://app.smallco.io/api", data={}, grant_id=gid)
    hc.post("https://app.smallco.io/api", data={}, grant_id=gid)
    with pytest.raises(PermissionError):
        hc.post("https://app.smallco.io/api", data={}, grant_id=gid)
    assert len(calls) == 2


def test_active_daily_cap_separate_from_passive(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "k")
    hc, conn = _hc(tmp_path, lambda r: httpx.Response(200), active_daily=1)
    gid = create_grant(conn, "h1:1", "idor", "probe", 24, 10)
    hc.get("https://app.smallco.io/")                     # passive, plenty of room
    hc.post("https://app.smallco.io/api", data={}, grant_id=gid)
    with pytest.raises(BudgetExceeded):
        hc.post("https://app.smallco.io/api", data={}, grant_id=gid)


def test_post_out_of_scope_refused_even_with_grant(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "k")
    calls = []
    hc, conn = _hc(tmp_path, lambda r: calls.append(1) or httpx.Response(200))
    gid = create_grant(conn, "h1:1", "idor", "probe", 24, 10)
    with pytest.raises(OutOfScope):
        hc.post("https://not-smallco.io/api", data={}, grant_id=gid)
    assert calls == []


def test_post_evidence_captured(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "k")
    hc, conn = _hc(tmp_path, lambda r: httpx.Response(200, text="done"))
    gid = create_grant(conn, "h1:1", "idor", "probe", 24, 10)
    hc.post("https://app.smallco.io/api", data={"a": "b"}, grant_id=gid)
    dirs = list((tmp_path / "var/evidence/h1_1").iterdir())
    req_text = (dirs[0] / "001_req.http").read_text(encoding="utf-8")
    assert "POST https://app.smallco.io/api" in req_text and "a=b" in req_text


def test_expired_grant_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "k")
    hc, conn = _hc(tmp_path, lambda r: httpx.Response(200))
    gid = create_grant(conn, "h1:1", "idor", "probe", -1, 10)  # ttl in the past
    with pytest.raises(PermissionError):
        hc.post("https://app.smallco.io/api", data={}, grant_id=gid)
