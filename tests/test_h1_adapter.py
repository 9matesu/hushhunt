import json
from pathlib import Path

import httpx

from hushhunt.adapters.hackerone import HackerOneAdapter, parse_scope
from hushhunt.config import Config
from hushhunt.db import open_db

FIXTURE = Path(__file__).parent / "fixtures" / "h1_programs.json"


def _fake_client_factory():
    page = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.host == "api.hackerone.com"
        assert req.headers["Authorization"].startswith("Basic ")
        return httpx.Response(200, json=page)

    return lambda **kw: httpx.Client(transport=httpx.MockTransport(handler),
                                     auth=kw.get("auth"))


def _cfg(tmp_path):
    return Config({"platforms": {"hackerone": {"enabled": True}}}, tmp_path)


def test_sync_programs_upserts_normalized_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_H1_USER", "matco")
    monkeypatch.setenv("HH_H1_API_TOKEN", "tok")
    conn = open_db(tmp_path / "t.db")
    n = HackerOneAdapter(client_factory=_fake_client_factory()).sync_programs(conn, _cfg(tmp_path))
    assert n == 2
    row = conn.execute("SELECT * FROM programs WHERE id='h1:101'").fetchone()
    assert row["safe_harbor"] == "all"
    assert row["max_bounty"] == 500
    scope = json.loads(row["scope_json"])
    assert scope["includes"] == ["*.smallco.io", "app.smallco.io"]
    assert set(scope["excludes"]) == {"blog.smallco.io", "staging.smallco.io"}
    assert row["created_at_remote"] == "2025-03-01T10:00:00.000Z"
    big = conn.execute("SELECT safe_harbor FROM programs WHERE id='h1:102'").fetchone()
    assert big["safe_harbor"] == "none"


def test_sync_stores_assets_rows(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_H1_USER", "u")
    monkeypatch.setenv("HH_H1_API_TOKEN", "t")
    conn = open_db(tmp_path / "t.db")
    HackerOneAdapter(client_factory=_fake_client_factory()).sync_programs(conn, _cfg(tmp_path))
    hosts = {r["identifier"] for r in conn.execute(
        "SELECT identifier FROM assets WHERE program_id='h1:101'")}
    assert hosts == {"*.smallco.io", "app.smallco.io"}


def test_parse_scope_ignores_other_asset_types():
    attrs = {"program_bounties": [{"asset_type": "OTHER", "identifier": "x"}]}
    includes, excludes = parse_scope(attrs)
    assert includes == [] and excludes == []


def test_adapter_requires_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv("HH_H1_USER", raising=False)
    monkeypatch.delenv("HH_H1_API_TOKEN", raising=False)
    conn = open_db(tmp_path / "t.db")
    try:
        HackerOneAdapter().sync_programs(conn, _cfg(tmp_path))
        assert False, "should raise"
    except RuntimeError as e:
        assert "HH_H1" in str(e)
