import json
from pathlib import Path

import httpx

from hushhunt.adapters.bugcrowd import BugcrowdAdapter
from hushhunt.config import Config
from hushhunt.db import open_db

FIXTURE = Path(__file__).parent / "fixtures" / "bc_bounties.json"


def _factory():
    page = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.host == "api.bugcrowd.com"
        assert req.headers["Authorization"] == "Token bc-key"
        assert req.headers["API-Version"] == "2"
        return httpx.Response(200, json=page)

    return lambda **kw: httpx.Client(transport=httpx.MockTransport(handler),
                                     headers=kw.get("headers"))


def test_sync_bugcrowd(tmp_path):
    cfg = Config({}, tmp_path)
    import os
    os.environ["HH_BC_TOKEN"] = "bc-key"
    conn = open_db(tmp_path / "t.db")
    n = BugcrowdAdapter(client_factory=_factory()).sync_programs(conn, cfg)
    assert n == 2
    row = conn.execute("SELECT * FROM programs WHERE id='bc:9001'").fetchone()
    scope = json.loads(row["scope_json"])
    assert set(scope["includes"]) == {"shop.tinyshop.dev", "*.tinyshop.dev"}
    assert row["safe_harbor"] == "all" and row["max_bounty"] == 800
    # android package scope must be dropped entirely
    assert all("android" not in i and "com." not in i for i in scope["includes"])
    mega = conn.execute("SELECT safe_harbor FROM programs WHERE id='bc:9002'").fetchone()
    assert mega["safe_harbor"] == "none"
