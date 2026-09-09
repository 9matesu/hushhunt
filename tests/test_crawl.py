import httpx
import pytest

from hushhunt.config import Config
from hushhunt.crawl import crawl
from hushhunt.db import open_db, upsert_program

LIMITS = {"limits": {"rate_per_second_per_target": 10000,
                     "daily_requests_per_program": 100,
                     "max_requests_per_asset": 100,
                     "request_timeout_seconds": 5,
                     "user_agent": "t"}}


def _program(conn):
    upsert_program(conn, {"id": "h1:1", "platform": "hackerone", "name": "s",
                          "url": "", "safe_harbor": "all", "max_bounty": 1,
                          "avg_resolution_h": 0, "created_at_remote": None,
                          "policy_text": "",
                          "scope_json": '{"includes":["t.invalid"],"excludes":[]}'})
    conn.execute("INSERT INTO assets(program_id,asset_type,identifier,origin) "
                 "VALUES('h1:1','DOMAIN','t.invalid','program_scope')")
    conn.commit()


PROG = {"id": "h1:1", "name": "s", "includes": ["t.invalid"], "excludes": [],
        "safe_harbor": "all"}


def test_crawl_respects_robots_and_collects_params(tmp_path):
    from tests.vulnapp import handler
    conn = open_db(tmp_path / "c.db")
    _program(conn)
    result = crawl(Config(LIMITS, tmp_path), conn, PROG,
                   transport=httpx.MockTransport(handler), max_pages=10)
    assert result["pages"] >= 2
    params = {(r["url"], r["param"]) for r in conn.execute(
        "SELECT url, param FROM params_seen")}
    assert ("/search", "q") in params
    assert ("/item", "id") in params
    urls = [r["url"] for r in conn.execute("SELECT url FROM request_log")]
    assert not [u for u in urls if "/private/" in u]   # robots honored
    assert len(urls) <= 11                              # budget respected
    assert any(u.endswith("/robots.txt") for u in urls)


def test_same_origin_only(tmp_path):
    conn = open_db(tmp_path / "c.db")
    _program(conn)

    def h(req):
        if req.url.host == "t.invalid" and req.url.path == "/":
            return httpx.Response(200, text='<a href="https://evil.t.invalid/">x</a>'
                                             '<a href="/item?id=1">y</a>')
        return httpx.Response(200, text="")

    crawl(Config(LIMITS, tmp_path), conn, PROG,
          transport=httpx.MockTransport(h), max_pages=5)
    urls = [r["url"] for r in conn.execute("SELECT url FROM request_log")]
    assert not any("evil.t.invalid" in u for u in urls)
    assert any("/item" in u for u in urls)      # legit link was followed


def test_forms_collected(tmp_path):
    conn = open_db(tmp_path / "c.db")
    _program(conn)

    def h(req):
        return httpx.Response(200, text='<form action="/login">'
                                        '<input name="username"></form>')

    crawl(Config(LIMITS, tmp_path), conn, PROG,
          transport=httpx.MockTransport(h), max_pages=3)
    params = {(r["url"], r["param"]) for r in conn.execute(
        "SELECT url, param FROM params_seen")}
    assert ("/login", "username") in params
