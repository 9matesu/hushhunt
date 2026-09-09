import httpx

from hushhunt.config import Config
from hushhunt.db import open_db, upsert_program
from hushhunt.checks import Ctx
from hushhunt.checks.active.redirect import check_open_redirect
from hushhunt.checks.active.graphql import check_graphql
import hushhunt.checks.active.redirect, hushhunt.checks.active.graphql  # register
from hushhunt.grants import create_grant
from hushhunt.http import HardenedClient
from tests.vulnapp import handler, safe_handler

REDIRECT_URL = "https://t.invalid/redirect?url=/home"


import pytest


@pytest.fixture(autouse=True)
def _grant_secret(monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "testkey")


def _ctx(h, params=None, with_grant=False, tmp_path=None):
    calls = []

    def fetch(url, headers=None):
        calls.append(("GET", str(url)))
        return httpx.Client(transport=httpx.MockTransport(h)).get(url)

    ctx = Ctx(resp=httpx.Response(200, request=httpx.Request("GET", REDIRECT_URL)),
              fetch=fetch)
    ctx.params = params or [(REDIRECT_URL, "url", "/home")]
    if with_grant:
        conn = open_db(tmp_path / "g.db")
        upsert_program(conn, {"id": "h1:1", "platform": "hackerone", "name": "s",
                              "url": "", "safe_harbor": "all", "max_bounty": 1,
                              "avg_resolution_h": 0, "created_at_remote": None,
                              "policy_text": "", "scope_json": "{}"})
        gid = create_grant(conn, "h1:1", "graphql_probe", "probe", 24, 20)
        cfg = Config({"limits": {
            "rate_per_second_per_target": 1000, "daily_requests_per_program": 999,
            "max_requests_per_asset": 99, "request_timeout_seconds": 5,
            "user_agent": "t", "active": {
                "daily_requests_per_program": 999, "burst_rate_per_second": 1000}}},
            tmp_path)
        hc = HardenedClient(conn, cfg, {"id": "h1:1", "name": "s",
                                        "includes": ["t.invalid"], "excludes": []},
                            transport=httpx.MockTransport(h))
        ctx.post = lambda url, json_body=None, grant_id=None: hc.post(
            url, json_body=json_body, grant_id=gid)
        ctx.grant_id = gid
    return ctx, calls


def test_open_redirect_flagged_on_vulnapp():
    ctx, calls = _ctx(handler)
    out = check_open_redirect(ctx)
    assert len(out) == 1
    assert "hushhunt-canary.invalid" in out[0]["payload"]["location"]
    assert len(calls) == 1                      # single probe


def test_safe_redirect_pinned_home_zero():
    ctx, _ = _ctx(safe_handler)
    assert check_open_redirect(ctx) == []


def test_non_url_params_ignored():
    ctx, calls = _ctx(handler, params=[("https://t.invalid/x?page=2", "page", "2"),
                                       ("https://t.invalid/x?query=q", "query", "q")])
    assert check_open_redirect(ctx) == []
    assert calls == []                          # never even probes non-URL params


def test_graphql_introspection_flagged(tmp_path):
    ctx, calls = _ctx(handler, with_grant=True, tmp_path=tmp_path)
    ctx.graphql_urls = ["https://t.invalid/graphql"]
    out = check_graphql(ctx)
    assert len(out) == 1
    assert out[0]["payload"]["issue"] == "introspection_open"
    assert all(m == "POST" for m, _ in calls)   # exactly the POSTs, no GETs


def test_graphql_safe_app_zero(tmp_path):
    ctx, _ = _ctx(safe_handler, with_grant=True, tmp_path=tmp_path)
    ctx.graphql_urls = ["https://t.invalid/graphql"]
    assert check_graphql(ctx) == []


def test_graphql_needs_grant_for_post(tmp_path):
    ctx, _ = _ctx(handler, tmp_path=tmp_path)   # with_grant False -> post None
    ctx.graphql_urls = ["https://t.invalid/graphql"]
    assert check_graphql(ctx) == []
