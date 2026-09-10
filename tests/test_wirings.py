import pytest


def test_hardened_client_rotates_proxy_pool():
    from hushhunt.http import HardenedClient
    from hushhunt.proxy_pool import ProxyPool

    pool = ProxyPool(["http://proxy-a:8080", "http://proxy-b:8080"])
    assert pool.total == 2
    seen = {pool.get_next_proxy(), pool.get_next_proxy(), pool.get_next_proxy()}
    assert seen == {"http://proxy-a:8080", "http://proxy-b:8080"}


def test_param_miner_wired_to_pipeline(tmp_path):
    import httpx
    from hushhunt.param_miner import find_hidden_params
    from tests.vulnapp import handler

    client = httpx.Client(transport=httpx.MockTransport(handler))
    res = find_hidden_params(client, "https://t.invalid/search", candidate_params=["q", "zz_nope_9"])
    found = [r["param"] for r in res]
    assert "q" in found and "zz_nope_9" not in found


def test_drift_wired_to_probe(tmp_path):
    import sqlite3
    from hushhunt.drift import check_drift, init_drift_table

    conn = sqlite3.connect(":memory:")
    init_drift_table(conn)
    assert check_drift(conn, "https://t.invalid/app", 200, "v1") == (False, "baseline")
    changed, note = check_drift(conn, "https://t.invalid/app", 200, "v2!")
    assert changed is True and "content changed" in note


def test_schema_miner_wired_to_pipeline():
    from hushhunt.schema_miner import parse_graphql_types, parse_openapi_paths

    eps = parse_openapi_paths({"paths": {"/api/orders": {"get": {"summary": "list"}}}})
    assert eps and eps[0]["path"] == "/api/orders"
    assert parse_graphql_types({"data": {"__schema": {"types": [{"name": "Q", "fields": [{"name": "me"}]}]}}}) == ["me"]


def test_session_manager_wired_to_broker():
    import httpx
    from hushhunt.session_manager import ResilientSession

    def h(req):
        return httpx.Response(200, json={"ok": 1}) if req.headers.get("Authorization") == "Bearer f" else httpx.Response(401)
    rs = ResilientSession(httpx.Client(transport=httpx.MockTransport(h)),
                          reauth_fn=lambda: {"Authorization": "Bearer f"},
                          initial_headers={"Authorization": "Bearer stale"})
    assert rs.get("https://t.invalid/x").status_code == 200
