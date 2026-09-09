import json
from pathlib import Path

import httpx

from hushhunt.ctlogs import discover
from hushhunt.db import open_db, upsert_program, add_asset

FIXTURE = [
    {"common_name": "*.smallco.io", "name_value": "*.smallco.io\napi.smallco.io\ndev.smallco.io"},
    {"common_name": "blog.smallco.io", "name_value": "blog.smallco.io"},
    {"common_name": "x", "name_value": "evil-smallco.io.attacker.net"},
]


def _program(conn):
    upsert_program(conn, {"id": "h1:1", "platform": "hackerone", "name": "S", "url": "",
                          "safe_harbor": "all", "max_bounty": 100, "avg_resolution_h": 0.0,
                          "created_at_remote": None, "policy_text": "",
                          "scope_json": json.dumps({"includes": ["*.smallco.io"],
                                                    "excludes": ["blog.smallco.io"]})})


def _factory():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.host == "crt.sh"
        return httpx.Response(200, json=FIXTURE)
    return lambda **kw: httpx.Client(transport=httpx.MockTransport(handler))


def test_discovery_adds_only_in_scope_hosts(tmp_path):
    conn = open_db(tmp_path / "t.db")
    _program(conn)
    prog = {"id": "h1:1", "name": "S", "includes": ["*.smallco.io"],
            "excludes": ["blog.smallco.io"], "safe_harbor": "all"}
    added = discover(conn, {"limits": {}}, prog, client_factory=_factory())
    assert set(added) == {"api.smallco.io", "dev.smallco.io"}
    stored = {r["identifier"] for r in conn.execute(
        "SELECT identifier FROM assets WHERE origin='ct_log'")}
    assert stored == {"api.smallco.io", "dev.smallco.io"}


def test_idempotent_second_run(tmp_path):
    conn = open_db(tmp_path / "t.db")
    _program(conn)
    prog = {"id": "h1:1", "name": "S", "includes": ["*.smallco.io"],
            "excludes": ["blog.smallco.io"], "safe_harbor": "all"}
    discover(conn, {}, prog, client_factory=_factory())
    second = discover(conn, {}, prog, client_factory=_factory())
    assert second == []


def test_wildcard_cert_names_not_added_verbatim(tmp_path):
    conn = open_db(tmp_path / "t.db")
    _program(conn)
    prog = {"id": "h1:1", "name": "S", "includes": ["*.smallco.io"],
            "excludes": [], "safe_harbor": "all"}
    added = discover(conn, {}, prog, client_factory=_factory())
    assert "*.smallco.io" not in added  # wildcard is not a connectable host
