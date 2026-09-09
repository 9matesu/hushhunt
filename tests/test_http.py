import sqlite3

import httpx
import pytest

from hushhunt.db import open_db, upsert_program, count_requests_today
from hushhunt.http import BudgetExceeded, HardenedClient, OutOfScope


def _cfg(tmp_path, daily=150, per_asset=12):
    from hushhunt.config import Config
    data = {"limits": {"rate_per_second_per_target": 1000,  # effectively no sleep in tests
                       "daily_requests_per_program": daily,
                       "max_requests_per_asset": per_asset,
                       "request_timeout_seconds": 5,
                       "user_agent": "hushhunt-test"}}
    return Config(data, tmp_path)


def _program():
    return {"id": "h1:1", "platform": "hackerone", "name": "SmallCo", "url": "u",
            "safe_harbor": "all", "max_bounty": 500, "avg_resolution_h": 0.0,
            "created_at_remote": None, "policy_text": "", "scope_json": ""}


def _client(tmp_path, handler, daily=150, per_asset=12):
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, _program())
    cfg = _cfg(tmp_path, daily=daily, per_asset=per_asset)
    prog = {"id": "h1:1", "name": "SmallCo",
            "includes": ["*.smallco.io"], "excludes": ["blog.smallco.io"]}
    hc = HardenedClient(conn, cfg, prog)
    hc._client = httpx.Client(transport=httpx.MockTransport(handler),
                              headers=hc._client.headers, timeout=5)
    return hc, conn


def test_out_of_scope_never_touches_network(tmp_path):
    calls = []
    def h(req): calls.append(req.url); return httpx.Response(200)
    hc, conn = _client(tmp_path, h)
    with pytest.raises(OutOfScope):
        hc.get("https://evil-notsmallco.io/robots.txt")
    with pytest.raises(OutOfScope):
        hc.get("https://blog.smallco.io/")   # excluded
    assert calls == []
    assert count_requests_today(conn, "h1:1") == 0


def test_daily_budget_enforced(tmp_path):
    def h(req): return httpx.Response(200)
    hc, conn = _client(tmp_path, h, daily=3)
    for i in range(3):
        hc.get(f"https://a{i}.smallco.io/")
    with pytest.raises(BudgetExceeded):
        hc.get("https://a9.smallco.io/")


def test_per_asset_cap_enforced(tmp_path):
    calls = []
    def h(req): calls.append(req.url); return httpx.Response(200)
    hc, conn = _client(tmp_path, h, per_asset=5)
    for _ in range(5):
        hc.get("https://app.smallco.io/page")
    with pytest.raises(BudgetExceeded):
        hc.get("https://app.smallco.io/other")
    assert len(calls) == 5


def test_redirects_not_followed_and_revalidated(tmp_path):
    calls = []
    def h(req):
        calls.append(str(req.url))
        if "smallco.io" in str(req.url):
            return httpx.Response(302, headers={"Location": "https://outside-target.dev/x"})
        return httpx.Response(200)
    hc, conn = _client(tmp_path, h)
    r = hc.get("https://www.smallco.io/")
    assert r.status_code == 302
    with pytest.raises(OutOfScope):
        hc.get(r.headers["location"])
    assert len(calls) == 1


def test_every_request_logged_with_evidence(tmp_path):
    def h(req): return httpx.Response(200, text="hello", headers={"X-Test": "1"})
    hc, conn = _client(tmp_path, h)
    r = hc.get("https://app.smallco.io/robots.txt")
    assert count_requests_today(conn, "h1:1") == 1
    row = conn.execute("SELECT url,status FROM request_log").fetchone()
    assert row["url"] == "https://app.smallco.io/robots.txt" and row["status"] == 200
    dirs = list((tmp_path / "var/evidence/h1_1").iterdir())
    assert len(dirs) == 1
    body = (dirs[0] / "001_resp.http").read_text(encoding="utf-8")
    assert "200" in body and "hello" in body


def test_method_whitelist(tmp_path):
    """v1 rule: PUT/PATCH/DELETE/OPTIONS never exist. v2: POST exists but ONLY
    as the grant-gated hc.post(grant_id=...) — unauthenticated callers fail."""
    hc, _ = _client(tmp_path, lambda r: httpx.Response(200))
    for verb in ("put", "patch", "delete", "options"):
        with pytest.raises(AttributeError):
            getattr(hc, verb)("https://app.smallco.io/x")
    with pytest.raises(TypeError):        # post requires grant_id keyword
        hc.post("https://app.smallco.io/x")
    with pytest.raises(PermissionError):  # grant id 99 doesn't exist
        hc.post("https://app.smallco.io/x", data={}, grant_id=99)
